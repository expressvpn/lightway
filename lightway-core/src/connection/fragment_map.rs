use std::num::NonZeroU16;

use bytes::{Bytes, BytesMut};
use lru::LruCache;
use thiserror::Error;

use crate::wire;

/// Result of `FragmentMap::add_fragment`
pub(crate) enum FragmentMapResult {
    /// This packet is complete and can continue processing
    Complete(BytesMut),
    /// This packet is incomplete, more fragments are required
    Incomplete,
    /// An error occurred,
    Err(FragmentMapError),
}

/// Track and reconstruct packet fragments
pub(crate) struct FragmentMap(LruCache<u16, FragmentedPacket>);

impl FragmentMap {
    /// Default maximum entries for fragment reassembly cache.
    /// Set to u16::MAX for backwards compatibility, but production deployments
    /// should consider using a lower value (e.g., 256 or 512) to limit
    /// potential memory consumption from fragmented packet attacks.
    pub(crate) const DEFAULT_MAX_ENTRIES: NonZeroU16 = NonZeroU16::MAX;

    pub(crate) fn new(max_capacity: NonZeroU16) -> Self {
        Self(LruCache::new(max_capacity.into()))
    }

    /// Add `frag` to the map. If the given packet is now complete then
    /// return it.
    pub(crate) fn add_fragment(&mut self, frag: wire::DataFrag) -> FragmentMapResult {
        let id = frag.id;
        let fp = self.0.get_or_insert_mut(id, FragmentedPacket::new);

        if let Err(err) = fp.update(frag) {
            // No `entry` API for LRU so we must lookup again in
            // order to remove, which must succeed since we have a
            // mutable reference to the hash table (via
            // `self`). The existing value is no longer of
            // interest so discard
            self.0.pop(&id).unwrap();
            return FragmentMapResult::Err(err);
        }

        match fp.try_complete() {
            Some(b) => {
                // As above we must lookup again. The entry remaining
                // in the cache has been emptied by `try_complete`.
                let _ = self.0.pop(&id);
                FragmentMapResult::Complete(b)
            }
            None => FragmentMapResult::Incomplete,
        }
    }
}

/// Track a single fragmented packet
struct FragmentedPacket {
    fragments: Vec<Fragment>,
}

impl FragmentedPacket {
    fn new() -> Self {
        Self {
            fragments: Vec::with_capacity(4),
        }
    }

    fn update(&mut self, frag: wire::DataFrag) -> Result<()> {
        if frag.data.is_empty() {
            return Err(FragmentMapError::Empty);
        }

        for idx in 0..self.fragments.len() {
            let curr = &mut self.fragments[idx];

            // Check for overlap
            if frag.end_offset() > curr.start && frag.start_offset() < curr.end() {
                return Err(FragmentMapError::Overlapping);
            };

            // No overlaps, so now try to see where it will fit.
            if frag.end_offset() < curr.start {
                // New non-contiguous frag before the current
                // one. Cannot overlap the previous frag (if any) due
                // to checks above.
                self.fragments.insert(idx, Fragment::new(frag));
                return Ok(());
            } else if frag.end_offset() == curr.start || curr.end() == frag.start_offset() {
                // Contiguous right before or after this fragment
                curr.add_wire_frag(frag)?;

                // If we filled the gap between this frag and the next
                // then merge it into this one.
                //
                // We cannot require merging with the previous frag,
                // since that would have happened on the previous
                // iteration of this loop.
                if idx < self.fragments.len() - 1
                    && self.fragments[idx].end() == self.fragments[idx + 1].start
                {
                    let frag = self.fragments.remove(idx + 1);
                    self.fragments[idx].merge(frag)?;
                }

                return Ok(());
            }
            // Non-contiguous entry after `curr` will either be handled on
            // the next iteration of by the final case below.
        }

        // New non-contiguous frag after the last fragment or no fragments
        self.fragments.push(Fragment::new(frag));
        Ok(())
    }

    /// Attempt to get the complete packet, succeeds only if all
    /// fragments are available.
    ///
    /// Note that on success this empties self.
    fn try_complete(&mut self) -> Option<BytesMut> {
        if self.fragments.len() != 1 {
            return None;
        }
        if !self.fragments[0].is_complete_packet() {
            return None;
        }

        let frag = self.fragments.remove(0);
        debug_assert!(self.fragments.is_empty());

        let mut b = BytesMut::with_capacity(frag.size);
        b.extend(frag.data);

        Some(b)
    }
}

/// A single contiguous (but chunked) fragment of a fragmented packet
struct Fragment {
    start: usize,
    size: usize,
    is_last: bool,
    data: Vec<Bytes>,
}

impl Fragment {
    fn new(data: wire::DataFrag) -> Self {
        let wire::DataFrag {
            offset,
            more_fragments,
            data,
            ..
        } = data;

        Self {
            start: offset,
            size: data.len(),
            is_last: !more_fragments,
            data: vec![data],
        }
    }

    // The end offset, which is one past the final byte.
    fn end(&self) -> usize {
        self.start + self.size
    }

    // Is this fragment a complete packet.
    fn is_complete_packet(&self) -> bool {
        self.start == 0 && self.is_last
    }

    /// Combine next adjacent [`Fragment`] into `self`. The caller is
    /// responsible for ensuring that `next` is actually immediately
    /// after `self`. Will panic if this requirement is violated.
    fn merge(&mut self, mut next: Self) -> Result<()> {
        assert_eq!(self.end(), next.start, "Fragments are not contiguous");

        if self.is_last {
            return Err(FragmentMapError::AfterLast);
        }

        self.size += next.size;
        self.is_last = next.is_last;
        self.data.append(&mut next.data);
        Ok(())
    }

    /// Add a new `wire::DataFrag` to this Fragment. The caller is
    /// responsible for ensuring that `frag` is actually adjacent to
    /// `self`. Will panic if this requirement is violated.
    fn add_wire_frag(&mut self, frag: wire::DataFrag) -> Result<()> {
        if self.start == frag.end_offset() {
            if !frag.more_fragments {
                return Err(FragmentMapError::LastFragmentBeforeCurrentTail);
            }
            self.start = frag.start_offset();
            self.size += frag.data.len();
            self.data.insert(0, frag.data);
        } else if self.end() == frag.start_offset() {
            if self.is_last {
                return Err(FragmentMapError::AfterLast);
            }
            self.size += frag.data.len();
            self.data.push(frag.data);
            self.is_last = !frag.more_fragments;
        } else {
            panic!("New wire::DataFrag must be contiguous");
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum FragmentMapError {
    #[error("Empty fragment")]
    Empty,
    #[error("Fragment overlaps with existing data")]
    Overlapping,
    #[error("Last fragment is before existing fragment")]
    LastFragmentBeforeCurrentTail,
    #[error("Fragment is after last fragment")]
    AfterLast,
}

pub(crate) type Result<T> = std::result::Result<T, FragmentMapError>;

#[cfg(test)]
mod tests {
    use super::*;
    use more_asserts::*;
    use test_case::test_case;

    impl FragmentMapResult {
        fn unwrap(self) -> Option<BytesMut> {
            match self {
                FragmentMapResult::Complete(data) => Some(data),
                FragmentMapResult::Incomplete => None,
                FragmentMapResult::Err(err) => panic!("{err:?}"),
            }
        }

        fn unwrap_err(self) -> FragmentMapError {
            match self {
                FragmentMapResult::Complete(_) => {
                    panic!("called `FragmentMapResult::unwrap_err()` on a `Complete` value")
                }
                FragmentMapResult::Incomplete => {
                    panic!("called `FragmentMapResult::unwrap_err()` on a `Incomplete` value")
                }
                FragmentMapResult::Err(err) => err,
            }
        }
    }

    impl FragmentedPacket {
        fn debug_string(&self) -> String {
            let total_bytes: usize = self.fragments.iter().map(|f| f.size).sum();
            let mut s = format!("{total_bytes}: {{ ");
            let frags: String = itertools::intersperse(
                self.fragments.iter().map(Fragment::debug_string),
                ", ".to_string(),
            )
            .collect();
            s.push_str(&frags);
            s.push_str(" }");
            s
        }
    }

    impl Fragment {
        // Check meets initial conditions
        fn validate(&self) {
            assert_gt!(self.size, 0);
            assert!(!self.data.is_empty());
            let total: usize = self.data.iter().map(Bytes::len).sum();
            assert_eq!(self.size, total);
        }

        // format for test cases, `RANGE = STRING` trailing `.` if last
        fn debug_string(&self) -> String {
            let mut s = format!("{}..{} = ", self.start, self.end());

            for b in &self.data {
                s.push_str(std::str::from_utf8(b).unwrap());
            }

            if self.is_last {
                s.push('.');
            }

            s
        }
    }

    #[test_case(wire::DataFrag{ id: 0, offset: 12, more_fragments: true, data: b"aaa"[..].into() } => "12..15 = aaa"; "non-last")]
    #[test_case(wire::DataFrag{ id: 0, offset: 47, more_fragments: false, data: b"bbbb"[..].into() } => "47..51 = bbbb."; "last")]
    fn fragment_new(data: wire::DataFrag) -> String {
        Fragment::new(data).debug_string()
    }

    #[test_case(
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] },
        Fragment{ start: 8, size: 3, is_last: false, data: vec![b"bbb"[..].into()] }
        => "5..11 = aaabbb";
        "Simple not-last"
    )]
    #[test_case(
        Fragment{ start: 8, size: 3, is_last: false, data: vec![b"bbb"[..].into()] },
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] }
        => panics "Fragments are not contiguous";
        "Reversed"
    )]
    #[test_case(
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] },
        Fragment{ start: 8, size: 3, is_last: true, data: vec![b"bbb"[..].into()] }
        => "5..11 = aaabbb.";
        "merge last"
    )]
    #[test_case(
        Fragment{ start: 5, size: 3, is_last: true, data: vec![b"aaa"[..].into()] },
        Fragment{ start: 8, size: 3, is_last: false, data: vec![b"bbb"[..].into()] }
        => panics "AfterLast";
        "earlier is last"
    )]
    #[test_case(
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] },
        Fragment{ start: 10, size: 3, is_last: false, data: vec![b"bbb"[..].into()] }
        => panics "Fragments are not contiguous";
        "Non-contiguous"
    )]
    #[test_case(
        Fragment{ start: 10, size: 3, is_last: false, data: vec![b"bbb"[..].into()] },
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] }
        => panics "Fragments are not contiguous";
        "Reversed Non-contiguous"
    )]
    #[test_case(
        Fragment{ start: 5, size: 6, is_last: false, data: vec![b"aaa"[..].into(), b"bbb"[..].into()] },
        Fragment{ start: 11, size: 3, is_last: false, data: vec![b"ccc"[..].into()] }
        => "5..14 = aaabbbccc";
        "Multiple data in first"
    )]
    #[test_case(
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] },
        Fragment{ start: 8, size: 6, is_last: false, data: vec![b"bbb"[..].into(), b"ccc"[..].into()] }
        => "5..14 = aaabbbccc";
        "Multiple data in second"
    )]
    fn fragment_merge(mut a: Fragment, b: Fragment) -> String {
        a.validate();
        b.validate();
        a.merge(b).unwrap();
        a.debug_string()
    }

    #[test_case(
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] },
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"bbb"[..].into() }
        => "5..11 = aaabbb";
        "Simple not-last"
    )]
    #[test_case(
        Fragment{ start: 8, size: 3, is_last: false, data: vec![b"bbb"[..].into()] },
        wire::DataFrag{ id: 0, offset: 5, more_fragments: true, data: b"aaa"[..].into() }
        => "5..11 = aaabbb";
        "Reverse not-last"
    )]
    #[test_case(
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] },
        wire::DataFrag{ id: 0, offset: 8, more_fragments: false, data: b"bbb"[..].into() }
        => "5..11 = aaabbb.";
        "merge last"
    )]
    #[test_case(
        Fragment{ start: 5, size: 3, is_last: true, data: vec![b"aaa"[..].into()] },
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"bbb"[..].into() }
        => panics "AfterLast";
        "earlier is last"
    )]
    #[test_case(
        Fragment{ start: 5, size: 3, is_last: false, data: vec![b"aaa"[..].into()] },
        wire::DataFrag{ id: 0, offset: 10, more_fragments: true, data: b"bbb"[..].into() }
        => panics "New wire::DataFrag must be contiguous";
        "Non-contiguous"
    )]
    #[test_case(
        Fragment{ start: 10, size: 3, is_last: false, data: vec![b"bbb"[..].into()] },
        wire::DataFrag{ id: 0, offset: 5, more_fragments: true, data: b"aaa"[..].into() }
        => panics "New wire::DataFrag must be contiguous";
        "Reverse Non-contiguous"
    )]
    #[test_case(
        Fragment{ start: 5, size: 6, is_last: false, data: vec![b"aaa"[..].into(), b"bbb"[..].into()] },
        wire::DataFrag{ id: 0, offset: 11, more_fragments: true, data: b"ccc"[..].into() }
        => "5..14 = aaabbbccc";
        "Multiple data in Fragment, new after"
    )]
    #[test_case(
        Fragment{ start: 8, size: 6, is_last: false, data: vec![b"bbb"[..].into(), b"ccc"[..].into()] },
        wire::DataFrag{ id: 0, offset: 5, more_fragments: true, data: b"aaa"[..].into() }
        => "5..14 = aaabbbccc";
        "Multiple data in Fragment, new before"
    )]
    fn fragment_add_wire_frag(mut a: Fragment, b: wire::DataFrag) -> String {
        a.validate();
        a.add_wire_frag(b).unwrap();
        a.debug_string()
    }

    fn fragment_with_gaps() -> FragmentedPacket {
        let mut fp = FragmentedPacket::new();
        for wire in [
            wire::DataFrag {
                id: 0,
                offset: 16,
                more_fragments: true,
                data: b"cccccccc"[..].into(),
            },
            wire::DataFrag {
                id: 0,
                offset: 32,
                more_fragments: true,
                data: b"eeeeeeee"[..].into(),
            },
        ] {
            fp.update(wire).unwrap();
        }
        assert_eq!(
            fp.debug_string(),
            "16: { 16..24 = cccccccc, 32..40 = eeeeeeee }"
        );
        fp
    }

    #[test_case([
        wire::DataFrag{ id: 0, offset: 0, more_fragments: true, data: b"aaaaaaaa"[..].into() }
    ] => "24: { 0..8 = aaaaaaaa, 16..24 = cccccccc, 32..40 = eeeeeeee }"; "non-contiguous prefix")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 48, more_fragments: true, data: b"gggggggg"[..].into() }
    ] => "24: { 16..24 = cccccccc, 32..40 = eeeeeeee, 48..56 = gggggggg }"; "new non-contiguous tail")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 40, more_fragments: false, data: b"ffffffff"[..].into() }
    ] => "24: { 16..24 = cccccccc, 32..48 = eeeeeeeeffffffff. }"; "new contiguous tail")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() }
    ] => "24: { 16..40 = ccccccccddddddddeeeeeeee }"; "fill gap")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 0, more_fragments: true, data: b"aaaaaaaa"[..].into() },
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"bbbbbbbb"[..].into() },
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() },
        wire::DataFrag{ id: 0, offset: 40, more_fragments: false, data: b"ffffffff"[..].into() }
    ] => "48: { 0..48 = aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff. }"; "finalize packet")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 40, more_fragments: false, data: b"ffffffff"[..].into() },
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"bbbbbbbb"[..].into() },
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() },
        wire::DataFrag{ id: 0, offset: 0, more_fragments: true, data: b"aaaaaaaa"[..].into() }
    ] => "48: { 0..48 = aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff. }"; "finalize packet out of order")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"xxxxxxxxxxxx"[..].into()}
    ] => panics "Overlapping"; "overlap at start of existing fragment")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"xxxxxxxxxxxxxxxxxxxxxxxx"[..].into() }
    ] => panics "Overlapping"; "complete overlap over existing fragment")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() },
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"xxxx"[..].into() }
    ] => panics "Overlapping"; "complete overlap within existing fragment")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() },
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"xxxxxxxxxxxxxxxxxxxx"[..].into() }
    ] => panics "Overlapping"; "overlap at end of existing fragment")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 40, more_fragments: false, data: b"ffffffff"[..].into() },
        wire::DataFrag{ id: 0, offset: 48, more_fragments: false, data: b"gggggggg"[..].into() }
    ] => panics "AfterLast"; "new last frag after existing last frag")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 48, more_fragments: false, data: b"gggggggg"[..].into() },
        wire::DataFrag{ id: 0, offset: 40, more_fragments: false, data: b"ffffffff"[..].into() }
    ] => panics "AfterLast"; "new last frag before existing last frag")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 8, more_fragments: false, data: b"bbbbbbbb"[..].into() },
    ] => panics "LastFragmentBeforeCurrentTail"; "new last frag before existing non-last frag")]
    #[test_case([
        wire::DataFrag { id: 0, offset: 0, more_fragments: true, data: b""[..].into() }
    ] => panics "Empty"; "empty frag")]
    fn fragmented_packet_update<const N: usize>(wire_frags: [wire::DataFrag; N]) -> String {
        let mut fp = fragment_with_gaps();
        for wire in wire_frags {
            fp.update(wire).unwrap();
        }
        fp.debug_string()
    }

    #[test_case([] => None; "holes")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() }
    ] => None; "missing prefix")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 0, more_fragments: true, data: b"aaaaaaaa"[..].into() },
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"bbbbbbbb"[..].into() },
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() }
    ] => None; "missing last")]
    #[test_case([
        wire::DataFrag{ id: 0, offset: 0, more_fragments: true, data: b"aaaaaaaa"[..].into() },
        wire::DataFrag{ id: 0, offset: 8, more_fragments: true, data: b"bbbbbbbb"[..].into() },
        wire::DataFrag{ id: 0, offset: 24, more_fragments: true, data: b"dddddddd"[..].into() },
        wire::DataFrag{ id: 0, offset: 40, more_fragments: false, data: b"ffffffff"[..].into() }
    ] => Some(b"aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff"[..].into()); "complete")]
    fn fragmented_packet_try_complete<const N: usize>(
        wire_frags: [wire::DataFrag; N],
    ) -> Option<BytesMut> {
        let mut fp = fragment_with_gaps();
        for wire in wire_frags {
            fp.update(wire).unwrap();
        }
        let b = fp.try_complete()?;

        assert!(fp.fragments.is_empty());

        Some(b)
    }

    #[test]
    fn fragment_map_reconstruct_packet() {
        let id = 23493;
        let mut fmap = FragmentMap::new(NonZeroU16::new(1).unwrap());

        let r = fmap
            .add_fragment(wire::DataFrag {
                id,
                offset: 0,
                more_fragments: true,
                data: b"aaaaaaaa"[..].into(),
            })
            .unwrap();
        assert!(r.is_none(), "Packet should be incomplete");
        assert!(
            fmap.0.contains(&id),
            "Partial packet should remain in cache"
        );

        let r = fmap
            .add_fragment(wire::DataFrag {
                id,
                offset: 8,
                more_fragments: false,
                data: b"bbbbbbbb"[..].into(),
            })
            .unwrap()
            .expect("Complete packet");

        assert_eq!(r, b"aaaaaaaabbbbbbbb"[..]);
        assert!(
            !fmap.0.contains(&id),
            "Complete packet should be removed from cache"
        )
    }

    #[test]
    fn fragment_map_discard_on_error() {
        let id = 26232;
        let mut fmap = FragmentMap::new(NonZeroU16::new(1).unwrap());

        let r = fmap
            .add_fragment(wire::DataFrag {
                id,
                offset: 0,
                more_fragments: true,
                data: b"aaaaaaaabbbbbbbb"[..].into(),
            })
            .unwrap();
        assert!(r.is_none(), "Packet should be incomplete");
        assert!(
            fmap.0.contains(&id),
            "Partial packet should remain in cache"
        );

        let e = fmap
            .add_fragment(wire::DataFrag {
                id,
                offset: 8,
                more_fragments: false,
                data: b"bbbbbb"[..].into(),
            })
            .unwrap_err();
        assert!(matches!(e, FragmentMapError::Overlapping));

        assert!(
            !fmap.0.contains(&id),
            "Packet should be removed from cache on error"
        );
    }
}

use std::{
    collections::{HashMap, hash_map},
    hash::Hash,
    net::SocketAddr,
    sync::Arc,
};
use thiserror::Error;

use lightway_core::SessionId;

#[derive(Error, Debug)]
pub(crate) enum InsertError {
    #[error("Insert with different SocketAddr to initial lookup")]
    InconsistentSocketAddr,

    #[error("Insert using reserved SessionId")]
    InsertReservedSessionId,
}

/// Identity of a connection for its whole life. Peer address and
/// session id can change. The server routes only datagram connections
/// by address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ConnectionId(pub(crate) u64);

pub(crate) trait Value {
    fn id(&self) -> ConnectionId;
    fn socket_addr(&self) -> SocketAddr;
    fn session_id(&self) -> SessionId;
}

pub(crate) struct VacantEntry<'a, T> {
    socket_addr_entry: hash_map::VacantEntry<'a, SocketAddr, Arc<T>>,
    by_id: &'a mut HashMap<ConnectionId, Arc<T>>,

    // For `SessionId` we insert via a new lookup not a `VacantEntry`
    // since for a new connection the session id isn't assigned until
    // after we've done the lookup to find we don't already know about
    // it -- so the session id which would be embedded into a
    // `VacantEntry` would not be the final one (it's probably
    // `SessionId::EMPTY`).
    session_id_map: &'a mut HashMap<SessionId, Arc<T>>,
}

impl<T: Value> VacantEntry<'_, T> {
    pub(crate) fn insert(self, value: &Arc<T>) -> Result<(), InsertError> {
        if self.socket_addr_entry.key() != &value.socket_addr() {
            return Err(InsertError::InconsistentSocketAddr);
        };
        if value.session_id().is_reserved() {
            return Err(InsertError::InsertReservedSessionId);
        };

        self.by_id.insert(value.id(), value.clone());
        self.socket_addr_entry.insert(value.clone());
        self.session_id_map
            .insert(value.session_id(), value.clone());
        Ok(())
    }
}

pub(crate) enum Entry<'a, T> {
    Occupied(Arc<T>),
    Vacant(VacantEntry<'a, T>),
}

/// Every connection is in `by_id`. Every entry of the other two
/// indexes points at a connection in `by_id`. Only datagram
/// connections have a `by_socket_addr` entry.
///
/// `remove` finds the entries of a connection by its `socket_addr` and
/// its `session_id`, so these are the keys. One exception: in a session
/// id rotation, the connection takes the new id first, and the key stays
/// the old id until `update_session_id_for_connection`. A removal in that
/// gap leaves the entry for the old id, which points at no connection in
/// `by_id`, until that call drops it.
pub(crate) struct ConnectionMap<T> {
    by_id: HashMap<ConnectionId, Arc<T>>,
    by_socket_addr: HashMap<SocketAddr, Arc<T>>,
    by_session_id: HashMap<SessionId, Arc<T>>,
}

impl<T> Default for ConnectionMap<T> {
    fn default() -> Self {
        Self {
            by_id: Default::default(),
            by_socket_addr: Default::default(),
            by_session_id: Default::default(),
        }
    }
}

impl<T> ConnectionMap<T> {
    pub(crate) fn iter_connections(
        &self,
    ) -> std::collections::hash_map::Values<'_, ConnectionId, Arc<T>> {
        self.by_id.values()
    }

    pub(crate) fn remove_connections(&mut self) -> Vec<Arc<T>> {
        self.by_session_id.clear();
        self.by_socket_addr.clear();
        self.by_id.drain().map(|e| e.1).collect()
    }

    pub(crate) fn lookup(&mut self, sock: SocketAddr, session: SessionId) -> Entry<'_, T> {
        let socket_addr_entry = self.by_socket_addr.entry(sock);

        match socket_addr_entry {
            hash_map::Entry::Occupied(e) => Entry::Occupied(e.get().clone()),
            hash_map::Entry::Vacant(sa_entry) => {
                let session_id_entry = self.by_session_id.entry(session);
                match session_id_entry {
                    hash_map::Entry::Occupied(e) => Entry::Occupied(e.get().clone()),
                    hash_map::Entry::Vacant(_) => Entry::Vacant(VacantEntry {
                        socket_addr_entry: sa_entry,
                        by_id: &mut self.by_id,
                        session_id_map: &mut self.by_session_id,
                    }),
                }
            }
        }
    }

    pub(crate) fn find_by(&mut self, sock: SocketAddr) -> Option<Arc<T>> {
        self.by_socket_addr.get(&sock).cloned()
    }

    pub(crate) fn find_by_session(&self, session: SessionId) -> Option<Arc<T>> {
        self.by_session_id.get(&session).cloned()
    }

    /// Whether `new_addr` is free for `value` to move onto: either unmapped,
    /// or already mapped to `value` itself.
    ///
    /// A move onto an address that another connection holds overwrites the
    /// entry of that connection, and the datagram server then cannot route
    /// to it.
    pub(crate) fn can_take_socketaddr(&self, new_addr: SocketAddr, value: &Arc<T>) -> bool {
        match self.by_socket_addr.get(&new_addr) {
            Some(existing) => Arc::ptr_eq(existing, value),
            None => true,
        }
    }
}

impl<T: Value> ConnectionMap<T> {
    /// Update the current connection mapped by `old_addr` to be
    /// mapped instead by `new_addr`.
    ///
    /// If the entry for `old_addr` is not `value` then this method
    /// is a nop.
    pub(crate) fn update_socketaddr_for_connection(
        &mut self,
        value: &T,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) {
        if let Some(entry) = remove_owned(&mut self.by_socket_addr, &old_addr, value.id()) {
            self.by_socket_addr.insert(new_addr, entry);
        }
    }

    /// Update the current connection mapped by [`SessionId`] `old` to
    /// be mapped instead by `new`.
    ///
    /// If the entry for `old` is not `value` then this method is a
    /// nop. If `value` is no longer in `by_id`, drop the entry for `old`.
    pub(crate) fn update_session_id_for_connection(
        &mut self,
        value: &T,
        old: SessionId,
        new: SessionId,
    ) {
        let id = value.id();
        let Some(entry) = remove_owned(&mut self.by_session_id, &old, id) else {
            return;
        };
        // The connection takes `new` before the map follows. A removal in
        // that gap leaves the entry for `old`, so drop it here. The entry
        // holds an `Arc`, so the connection stays alive and its rotation
        // event always calls this method.
        if self.by_id.contains_key(&id) {
            self.by_session_id.insert(new, entry);
        }
    }

    /// Insert a connection that the server does not route by peer address.
    pub(crate) fn insert(&mut self, value: &Arc<T>) -> Result<(), InsertError> {
        if value.session_id().is_reserved() {
            return Err(InsertError::InsertReservedSessionId);
        };

        self.by_id.insert(value.id(), value.clone());
        self.by_session_id.insert(value.session_id(), value.clone());

        Ok(())
    }

    pub(crate) fn remove(&mut self, value: &T) {
        let id = value.id();
        if self.by_id.remove(&id).is_none() {
            return;
        }
        remove_owned(&mut self.by_socket_addr, &value.socket_addr(), id);
        remove_owned(&mut self.by_session_id, &value.session_id(), id);
    }
}

/// Remove the entry for `key` only if it points at the connection `id`.
fn remove_owned<K: Eq + Hash, T: Value>(
    map: &mut HashMap<K, Arc<T>>,
    key: &K,
    id: ConnectionId,
) -> Option<Arc<T>> {
    if map.get(key)?.id() != id {
        return None;
    }
    map.remove(key)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    const SOCKET_ADDR_A: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1234);
    const SOCKET_ADDR_B: SocketAddr =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 4567);

    const SESSION_ID_A: SessionId =
        SessionId::from_const([0x11_u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const SESSION_ID_B: SessionId =
        SessionId::from_const([0x22_u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    #[derive(Debug)]
    struct V {
        id: ConnectionId,
        socket_addr: SocketAddr,
        session_id: SessionId,
    }

    impl Value for V {
        fn id(&self) -> ConnectionId {
            self.id
        }

        fn socket_addr(&self) -> std::net::SocketAddr {
            self.socket_addr
        }

        fn session_id(&self) -> lightway_core::SessionId {
            self.session_id
        }
    }

    /// Insert `v` with an entry for its peer address, as the
    /// datagram path does.
    fn insert_routed(m: &mut ConnectionMap<V>, v: &Arc<V>) {
        match m.lookup(v.socket_addr, SessionId::EMPTY) {
            Entry::Occupied(_) => panic!("Unexpected hit"),
            Entry::Vacant(e) => e.insert(v).unwrap(),
        }
    }

    #[test_case(SessionId::EMPTY => panics "`Err` value: InsertReservedSessionId")]
    #[test_case(SessionId::REJECTED => panics "`Err` value: InsertReservedSessionId")]
    fn inserting_reserved_ids_directly_is_not_tolerated(session_id: SessionId) {
        let mut m = ConnectionMap::<V>::default();
        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id,
        });
        m.insert(&v).unwrap()
    }

    #[test_case(SessionId::EMPTY => panics "`Err` value: InsertReservedSessionId")]
    #[test_case(SessionId::REJECTED => panics "`Err` value: InsertReservedSessionId")]
    fn inserting_reserved_ids_via_entry_is_not_tolerated(session_id: SessionId) {
        let mut m = ConnectionMap::<V>::default();
        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id,
        });

        match m.lookup(SOCKET_ADDR_A, session_id) {
            Entry::Occupied(_) => panic!("Unexpected hit"),
            Entry::Vacant(e) => e.insert(&v).unwrap(),
        }
    }

    #[test_case(SOCKET_ADDR_A, SESSION_ID_A => true;  "Both SocketAddr and SessionId match")]
    #[test_case(SOCKET_ADDR_B, SESSION_ID_B => false; "Neither SocketAddr nor SessionId match")]
    #[test_case(SOCKET_ADDR_B, SESSION_ID_A => true;  "Only SessionId matches")]
    #[test_case(SOCKET_ADDR_A, SESSION_ID_B => true;  "Only SocketAddr matches")] // Badly behaving client?
    fn lookup_works_by_socket_addr_or_session_id(
        socket_addr: SocketAddr,
        session_id: SessionId,
    ) -> bool {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });

        insert_routed(&mut m, &v);

        match m.lookup(socket_addr, session_id) {
            Entry::Occupied(f) => {
                assert!(Arc::ptr_eq(&v, &f));
                true
            }
            Entry::Vacant(_) => false,
        }
    }

    #[test_case(SOCKET_ADDR_A => SOCKET_ADDR_A; "SocketAddr present")]
    #[test_case(SOCKET_ADDR_B => panics "connection must exist")]
    fn find_works_by_socket_addr(socket_addr: SocketAddr) -> SocketAddr {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        insert_routed(&mut m, &v);

        let may_be_conn = m.find_by(socket_addr);
        may_be_conn.expect("connection must exist").socket_addr
    }

    #[test_case(SOCKET_ADDR_A ; "Consistent SocketAddr")]
    #[test_case(SOCKET_ADDR_B => panics "`Err` value: InconsistentSocketAddr" ; "Inconsistent SocketAddr")]
    fn insert_via_entry_works(socket_addr: SocketAddr) {
        let mut m = ConnectionMap::<V>::default();

        let session_id = SESSION_ID_A;
        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id,
        });

        match m.lookup(socket_addr, SessionId::EMPTY) {
            Entry::Occupied(_) => panic!("Should not be found"),
            Entry::Vacant(e) => e.insert(&v).unwrap(),
        }

        assert!(Arc::ptr_eq(&v, m.by_id.get(&v.id).unwrap()));
        assert!(Arc::ptr_eq(&v, m.by_socket_addr.get(&socket_addr).unwrap()));
        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&session_id).unwrap()));
    }

    #[test]
    fn changing_socket_addr_works() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });

        insert_routed(&mut m, &v);

        assert!(Arc::ptr_eq(
            &v,
            m.by_socket_addr.get(&SOCKET_ADDR_A).unwrap()
        ));
        assert!(!m.by_socket_addr.contains_key(&SOCKET_ADDR_B));
        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&SESSION_ID_A).unwrap()));

        let moved = V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_B,
            session_id: SESSION_ID_A,
        };
        m.update_socketaddr_for_connection(&moved, SOCKET_ADDR_A, SOCKET_ADDR_B);

        assert!(!m.by_socket_addr.contains_key(&SOCKET_ADDR_A));
        assert!(Arc::ptr_eq(
            &v,
            m.by_socket_addr.get(&SOCKET_ADDR_B).unwrap()
        ));
        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&SESSION_ID_A).unwrap()));

        m.remove(&moved);
        assert!(m.by_socket_addr.is_empty());
    }

    #[test]
    fn a_vacant_socketaddr_can_be_taken() {
        let mut m = ConnectionMap::<V>::default();
        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        insert_routed(&mut m, &v);

        assert!(m.can_take_socketaddr(SOCKET_ADDR_B, &v));
    }

    #[test]
    fn a_connection_can_retake_its_own_socketaddr() {
        let mut m = ConnectionMap::<V>::default();
        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        insert_routed(&mut m, &v);

        assert!(m.can_take_socketaddr(SOCKET_ADDR_A, &v));
    }

    /// Regression: a move onto an address that another connection holds
    /// overwrites its `by_socket_addr` entry, and the datagram server then
    /// cannot route to the displaced connection.
    #[test]
    fn a_socketaddr_another_connection_holds_cannot_be_taken() {
        let mut m = ConnectionMap::<V>::default();
        let held = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_B,
            session_id: SESSION_ID_B,
        });
        let mover = Arc::new(V {
            id: ConnectionId(2),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        insert_routed(&mut m, &held);
        insert_routed(&mut m, &mover);

        assert!(!m.can_take_socketaddr(SOCKET_ADDR_B, &mover));
    }

    #[test]
    fn changing_session_id_addr_works() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });

        insert_routed(&mut m, &v);

        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&SESSION_ID_A).unwrap()));
        assert!(!m.by_session_id.contains_key(&SESSION_ID_B));
        assert!(Arc::ptr_eq(
            &v,
            m.by_socket_addr.get(&SOCKET_ADDR_A).unwrap()
        ));

        m.update_session_id_for_connection(&v, SESSION_ID_A, SESSION_ID_B);

        assert!(!m.by_session_id.contains_key(&SESSION_ID_A));
        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&SESSION_ID_B).unwrap()));
        assert!(Arc::ptr_eq(
            &v,
            m.by_socket_addr.get(&SOCKET_ADDR_A).unwrap()
        ));
    }

    #[test]
    fn remove_works() {
        let mut m = ConnectionMap::<V>::default();

        let va = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let vb = Arc::new(V {
            id: ConnectionId(2),
            socket_addr: SOCKET_ADDR_B,
            session_id: SESSION_ID_B,
        });

        insert_routed(&mut m, &va);
        assert!(Arc::ptr_eq(
            &va,
            m.by_socket_addr.get(&SOCKET_ADDR_A).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &va,
            m.by_session_id.get(&SESSION_ID_A).unwrap()
        ));

        insert_routed(&mut m, &vb);
        assert!(Arc::ptr_eq(
            &vb,
            m.by_socket_addr.get(&SOCKET_ADDR_B).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &vb,
            m.by_session_id.get(&SESSION_ID_B).unwrap()
        ));

        m.remove(&va);

        assert!(!m.by_id.contains_key(&va.id));
        assert!(!m.by_socket_addr.contains_key(&SOCKET_ADDR_A));
        assert!(!m.by_session_id.contains_key(&SESSION_ID_A));

        assert!(Arc::ptr_eq(&vb, m.by_id.get(&vb.id).unwrap()));
        assert!(Arc::ptr_eq(
            &vb,
            m.by_socket_addr.get(&SOCKET_ADDR_B).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &vb,
            m.by_session_id.get(&SESSION_ID_B).unwrap()
        ));
    }

    #[test]
    fn iter_connections() {
        let mut m = ConnectionMap::<V>::default();

        let va = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let vb = Arc::new(V {
            id: ConnectionId(2),
            socket_addr: SOCKET_ADDR_B,
            session_id: SESSION_ID_B,
        });

        m.insert(&va).unwrap();

        let actual = m.iter_connections().cloned().collect::<Vec<_>>();
        assert_eq!(1, actual.len());
        assert!(Arc::ptr_eq(&actual[0], &va));

        m.insert(&vb).unwrap();

        let actual = m.iter_connections().cloned().collect::<Vec<_>>();
        assert_eq!(2, actual.len());

        if Arc::ptr_eq(&actual[0], &va) {
            assert!(Arc::ptr_eq(&actual[1], &vb));
        } else {
            assert!(Arc::ptr_eq(&actual[0], &vb));
            assert!(Arc::ptr_eq(&actual[1], &va));
        }
    }

    #[test]
    fn find_by_session_returns_the_mapped_connection() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        m.insert(&v).unwrap();

        let found = m.find_by_session(SESSION_ID_A).expect("session is mapped");
        assert!(Arc::ptr_eq(&v, &found));
        assert!(m.find_by_session(SESSION_ID_B).is_none());
    }

    #[test]
    fn find_by_session_follows_a_session_id_change() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        m.insert(&v).unwrap();
        m.update_session_id_for_connection(&v, SESSION_ID_A, SESSION_ID_B);

        assert!(m.find_by_session(SESSION_ID_A).is_none());
        let found = m
            .find_by_session(SESSION_ID_B)
            .expect("session is remapped");
        assert!(Arc::ptr_eq(&v, &found));
    }

    #[test]
    fn an_unrouted_connection_has_no_socket_addr_entry() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        m.insert(&v).unwrap();

        assert!(m.find_by(SOCKET_ADDR_A).is_none());
        assert!(matches!(
            m.lookup(SOCKET_ADDR_B, SESSION_ID_A),
            Entry::Occupied(f) if Arc::ptr_eq(&v, &f)
        ));
        assert_eq!(1, m.iter_connections().count());
    }

    #[test]
    fn remove_keeps_entries_that_belong_to_another_connection() {
        let mut m = ConnectionMap::<V>::default();

        let routed = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let unrouted = Arc::new(V {
            id: ConnectionId(2),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_B,
        });
        insert_routed(&mut m, &routed);
        m.insert(&unrouted).unwrap();

        m.remove(&unrouted);

        assert!(Arc::ptr_eq(&routed, &m.find_by(SOCKET_ADDR_A).unwrap()));
        assert!(!m.by_session_id.contains_key(&SESSION_ID_B));
        assert_eq!(1, m.iter_connections().count());
    }

    #[test]
    fn update_socketaddr_keeps_an_entry_that_belongs_to_another_connection() {
        let mut m = ConnectionMap::<V>::default();

        let routed = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let unrouted = Arc::new(V {
            id: ConnectionId(2),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_B,
        });
        insert_routed(&mut m, &routed);
        m.insert(&unrouted).unwrap();

        m.update_socketaddr_for_connection(&unrouted, SOCKET_ADDR_A, SOCKET_ADDR_B);

        assert!(Arc::ptr_eq(&routed, &m.find_by(SOCKET_ADDR_A).unwrap()));
        assert!(m.find_by(SOCKET_ADDR_B).is_none());
    }

    /// The connection takes its new session id before the map follows.
    /// A removal in that gap finds no entry for the new id.
    #[test]
    fn a_session_id_change_after_removal_adds_no_entry() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        m.insert(&v).unwrap();

        let rotated = V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_B,
        };
        m.remove(&rotated);
        m.update_session_id_for_connection(&rotated, SESSION_ID_A, SESSION_ID_B);

        assert!(m.by_session_id.is_empty());
    }

    #[test]
    fn update_session_id_keeps_an_entry_that_belongs_to_another_connection() {
        let mut m = ConnectionMap::<V>::default();

        let owner = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let other = Arc::new(V {
            id: ConnectionId(2),
            socket_addr: SOCKET_ADDR_B,
            session_id: SESSION_ID_B,
        });
        m.insert(&owner).unwrap();
        m.insert(&other).unwrap();

        m.update_session_id_for_connection(&other, SESSION_ID_A, SESSION_ID_B);

        assert!(Arc::ptr_eq(
            &owner,
            &m.find_by_session(SESSION_ID_A).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &other,
            &m.find_by_session(SESSION_ID_B).unwrap()
        ));
    }

    #[test]
    fn remove_connections_drains_unrouted_connections() {
        let mut m = ConnectionMap::<V>::default();

        let routed = Arc::new(V {
            id: ConnectionId(1),
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let unrouted = Arc::new(V {
            id: ConnectionId(2),
            socket_addr: SOCKET_ADDR_B,
            session_id: SESSION_ID_B,
        });
        insert_routed(&mut m, &routed);
        m.insert(&unrouted).unwrap();

        assert_eq!(2, m.remove_connections().len());
        assert_eq!(0, m.iter_connections().count());
        assert!(m.by_socket_addr.is_empty());
        assert!(m.by_session_id.is_empty());
    }
}

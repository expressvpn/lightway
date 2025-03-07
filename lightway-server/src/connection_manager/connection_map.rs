use std::{
    collections::{HashMap, hash_map},
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

pub(crate) trait Value {
    fn socket_addr(&self) -> SocketAddr;
    fn session_id(&self) -> SessionId;
}

pub(crate) struct VacantEntry<'a, T> {
    socket_addr_entry: hash_map::VacantEntry<'a, SocketAddr, Arc<T>>,

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

pub(crate) struct ConnectionMap<T> {
    by_socket_addr: HashMap<SocketAddr, Arc<T>>,
    by_session_id: HashMap<SessionId, Arc<T>>,
}

impl<T> Default for ConnectionMap<T> {
    fn default() -> Self {
        Self {
            by_socket_addr: Default::default(),
            by_session_id: Default::default(),
        }
    }
}

impl<T> ConnectionMap<T> {
    pub(crate) fn iter_connections(
        &self,
    ) -> std::collections::hash_map::Values<'_, SocketAddr, Arc<T>> {
        self.by_socket_addr.values()
    }

    pub(crate) fn get_all_connections(&self) -> Vec<Arc<T>> {
        self.by_socket_addr.values().cloned().collect()
    }

    pub(crate) fn remove_connections(&mut self) -> Vec<Arc<T>> {
        self.by_session_id.clear();
        self.by_socket_addr.drain().map(|e| e.1).collect()
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
                        session_id_map: &mut self.by_session_id,
                    }),
                }
            }
        }
    }

    pub(crate) fn find_by(&mut self, sock: SocketAddr) -> Option<Arc<T>> {
        self.by_socket_addr.get(&sock).cloned()
    }

    /// Update the current connection mapped by `old_addr` to be
    /// mapped instead by `new_addr`.
    ///
    /// If there is no current entry for `old_addr` then this method
    /// is a nop.
    pub(crate) fn update_socketaddr_for_connection(
        &mut self,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) {
        if let Some(value) = self.by_socket_addr.remove(&old_addr) {
            self.by_socket_addr.insert(new_addr, value);
        }
    }

    /// Update the current connection mapped by [`SessionId`] `old` to
    /// be mapped instead by `new`.
    ///
    /// If there is no current entry for `old` then this method is a
    /// nop.
    pub(crate) fn update_session_id_for_connection(&mut self, old: SessionId, new: SessionId) {
        if let Some(value) = self.by_session_id.remove(&old) {
            self.by_session_id.insert(new, value);
        }
    }
}

impl<T: Value> ConnectionMap<T> {
    pub(crate) fn insert(&mut self, value: &Arc<T>) -> Result<(), InsertError> {
        if value.session_id().is_reserved() {
            return Err(InsertError::InsertReservedSessionId);
        };

        self.by_socket_addr
            .insert(value.socket_addr(), value.clone());
        self.by_session_id.insert(value.session_id(), value.clone());

        Ok(())
    }

    pub(crate) fn remove(&mut self, value: &T) {
        self.by_socket_addr.remove(&value.socket_addr());
        self.by_session_id.remove(&value.session_id());
    }
}

// Tests START -> panic, unwrap, expect allowed
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
        socket_addr: SocketAddr,
        session_id: SessionId,
    }

    impl Value for V {
        fn socket_addr(&self) -> std::net::SocketAddr {
            self.socket_addr
        }

        fn session_id(&self) -> lightway_core::SessionId {
            self.session_id
        }
    }

    #[test_case(SessionId::EMPTY => panics "`Err` value: InsertReservedSessionId")]
    #[test_case(SessionId::REJECTED => panics "`Err` value: InsertReservedSessionId")]
    fn inserting_reserved_ids_directly_is_not_tolerated(session_id: SessionId) {
        let mut m = ConnectionMap::<V>::default();
        let v = Arc::new(V {
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
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });

        m.insert(&v).unwrap();

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
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        m.insert(&v).unwrap();

        let may_be_conn = m.find_by(socket_addr);
        may_be_conn.expect("connection must exist").socket_addr
    }

    #[test_case(SOCKET_ADDR_A ; "Consistent SocketAddr")]
    #[test_case(SOCKET_ADDR_B => panics "`Err` value: InconsistentSocketAddr" ; "Inconsistent SocketAddr")]
    fn insert_via_entry_works(socket_addr: SocketAddr) {
        let mut m = ConnectionMap::<V>::default();

        let session_id = SESSION_ID_A;
        let v = Arc::new(V {
            socket_addr: SOCKET_ADDR_A,
            session_id,
        });

        match m.lookup(socket_addr, SessionId::EMPTY) {
            Entry::Occupied(_) => panic!("Should not be found"),
            Entry::Vacant(e) => e.insert(&v).unwrap(),
        }

        assert!(Arc::ptr_eq(&v, m.by_socket_addr.get(&socket_addr).unwrap()));
        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&session_id).unwrap()));
    }

    #[test]
    fn changing_socket_addr_works() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });

        m.insert(&v).unwrap();

        assert!(Arc::ptr_eq(
            &v,
            m.by_socket_addr.get(&SOCKET_ADDR_A).unwrap()
        ));
        assert!(!m.by_socket_addr.contains_key(&SOCKET_ADDR_B));
        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&SESSION_ID_A).unwrap()));

        m.update_socketaddr_for_connection(SOCKET_ADDR_A, SOCKET_ADDR_B);

        assert!(!m.by_socket_addr.contains_key(&SOCKET_ADDR_A));
        assert!(Arc::ptr_eq(
            &v,
            m.by_socket_addr.get(&SOCKET_ADDR_B).unwrap()
        ));
        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&SESSION_ID_A).unwrap()));
    }

    #[test]
    fn changing_session_id_addr_works() {
        let mut m = ConnectionMap::<V>::default();

        let v = Arc::new(V {
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });

        m.insert(&v).unwrap();

        assert!(Arc::ptr_eq(&v, m.by_session_id.get(&SESSION_ID_A).unwrap()));
        assert!(!m.by_session_id.contains_key(&SESSION_ID_B));
        assert!(Arc::ptr_eq(
            &v,
            m.by_socket_addr.get(&SOCKET_ADDR_A).unwrap()
        ));

        m.update_session_id_for_connection(SESSION_ID_A, SESSION_ID_B);

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
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let vb = Arc::new(V {
            socket_addr: SOCKET_ADDR_B,
            session_id: SESSION_ID_B,
        });

        m.insert(&va).unwrap();
        assert!(Arc::ptr_eq(
            &va,
            m.by_socket_addr.get(&SOCKET_ADDR_A).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &va,
            m.by_session_id.get(&SESSION_ID_A).unwrap()
        ));

        m.insert(&vb).unwrap();
        assert!(Arc::ptr_eq(
            &vb,
            m.by_socket_addr.get(&SOCKET_ADDR_B).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &vb,
            m.by_session_id.get(&SESSION_ID_B).unwrap()
        ));

        m.remove(&va);

        assert!(!m.by_socket_addr.contains_key(&SOCKET_ADDR_A));
        assert!(!m.by_session_id.contains_key(&SESSION_ID_A));

        m.insert(&vb).unwrap();
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
            socket_addr: SOCKET_ADDR_A,
            session_id: SESSION_ID_A,
        });
        let vb = Arc::new(V {
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
}

// Tests END -> panic, unwrap, expect allowed

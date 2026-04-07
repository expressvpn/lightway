pub mod inside;
pub mod outside;

#[cfg(test)]
mod test {
    #[cfg(feature = "mobile")]
    #[tokio::test]
    async fn test_outside_socket_new_calls_created_outside_fd() {
        use super::*;
        use crate::mobile::MockEventHandlers;
        use std::sync::Arc;

        // Test TCP socket creation
        let mut mock_event_handler = MockEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let tcp_result = outside::OutsideSocket::new(true, Some(Arc::new(mock_event_handler)));
        assert!(tcp_result.is_ok());

        // Test UDP socket creation
        let mut mock_event_handler = MockEventHandlers::new();

        mock_event_handler
            .expect_created_outside_fd()
            .times(1)
            .return_const(());

        let udp_result = outside::OutsideSocket::new(false, Some(Arc::new(mock_event_handler)));
        assert!(udp_result.is_ok());
    }
}

# Connection State Machine

A `lightway_core::Connection` follows a simple lifecycle, described by
the `lightway_core::State` enum.

```mermaid
stateDiagram-v2
    direction TB
    Connecting: State#colon;#colon;Connecting
    LinkUp: State#colon;#colon;LinkUp
    Authenticating: State#colon;#colon;Authenticating
    Online: State#colon;#colon;Online
    Disconnecting: State#colon;#colon;Disconnecting
    Disconnected: State#colon;#colon;Disconnected

    %% Fake states for clarity in diagram
    AuthFailedDisconnecting: State#colon;#colon;Disconnecting

    note left of Connecting
      Secure (D)TLS connection negotiated

      tls#colon;#colon;Session#colon;#colon;try_negotiate()
      called until success or failure.
    end note

    [*] --> Connecting
    Connecting --> LinkUp: (D)TLS connection is established

    state client_server_auth <<fork>>
        LinkUp --> client_server_auth
        client_server_auth --> ClientAuth: Client#colon; Begins authenticating
        client_server_auth --> ServerAuth: Server#colon; Frame#colon;#colon;AuthRequest received

    state ClientAuth {
        [*] --> Authenticating
        Authenticating --> [*]: Frame#colon;#colon;AuthSuccessWithConfigV4 received
    }

    state ServerAuth {

        state if_state <<choice>>
            [*] --> if_state: Call to ServerAuth#colon;#colon;authorize() callback
            if_state
            if_state --> [*]: ServerAuthResult#colon;#colon;Granted
            if_state --> AuthFailedDisconnecting: ServerAuthResult#colon;#colon;Denied
    }

    state client_server_auth_done <<join>>
        ClientAuth --> client_server_auth_done
        ServerAuth --> client_server_auth_done
        client_server_auth_done --> Online

    %% LinkUp --> Disconnecting: Connection#colon;#colon;disconnect() method called
    %% Authenticating --> Disconnecting: Connection#colon;#colon;disconnect() method called
    Online --> Disconnecting: Connection#colon;#colon;disconnect() method called

    Disconnecting --> Disconnected
    Disconnected --> [*]
```

Some transitions are ommitted for clarity:

* If no DTLS traffic is received the `Connection::tick()` can transition
  directly to `State::Disconnected` from any state.
* A call to `Connection::disconnect()` will transition to
  `State::Disconnecting`.

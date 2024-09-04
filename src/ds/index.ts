type WebSocketData = {
    sessionId: string;
};

const server = Bun.serve<WebSocketData>({
    fetch(req, server) {
        if (
            server.upgrade(req, {
                data: {
                    sessionId: "lol"
                }
            })
        ) {
            return;
        }
        return new Response("Upgrade failed", { status: 500 });
    },
    websocket: {
        open(ws) {
            ws.send("Hello world!");
            ws.send(ws.data.sessionId);
            ws.data.sessionId = "lola";
        },
        message(ws, message) {
            ws.send(message);
            ws.send(ws.data.sessionId);
        }
    },
    port: 6270
});

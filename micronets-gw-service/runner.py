from app import app

if __name__ == '__main__':
    host = app.config ['LISTEN_HOST']
    port = app.config ['LISTEN_PORT']
    print(f"Starting gateway service on {host}:{port}")
    app.run (host, port)
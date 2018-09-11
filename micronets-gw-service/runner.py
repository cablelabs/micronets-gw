from app import app

if __name__ == '__main__':
    host = app.config ['LISTEN_HOST']
    port = app.config ['LISTEN_PORT']
    app.run (host, port)
# Damn Vulnerable OAuth 2.0 Applications

This project contains a vulnerable OAuth 2.0 server ([gallery](./gallery)), a vulnerable OAuth 2.0 classic web application client ([photoprint](./photoprint)), and an attackers site exploiting it all ([attacker](./attacker)).

To run the applications, you can use either **Docker Compose** or run them **directly on your host machine**.

## Option A: Docker (Recommended)

1. Execute docker compose:

    ```bash
    docker compose up
    ```

2. Open your browser and navigate directly to:
   - **PhotoPrint (Client)**: [http://photoprint.127.0.0.1.nip.io:3000](http://photoprint.127.0.0.1.nip.io:3000)
   - **Gallery (IdP/Resource Server)**: [http://gallery.127.0.0.1.nip.io:3005](http://gallery.127.0.0.1.nip.io:3005)
   - **Attacker Site (PoC Demos)**: [http://attacker.127.0.0.1.nip.io:1337](http://attacker.127.0.0.1.nip.io:1337)

   *(Optional: You can also open [http://localhost:7900](http://localhost:7900) in your browser with password `secret` to use the containerized Firefox browser via noVNC).*

## Option B: Running on Host

`gallery` and `photoprint` are now the Go ports described in [`../insecureapplication-go/README.md`](../insecureapplication-go/README.md) — see that file for how to run them without Docker (`make dev` in each directory, no configuration required for the `*.127.0.0.1.nip.io` setup below).

`attacker` is still Node.js:

1. Install the dependency:

    ```bash
    cd attacker && npm install
    ```

2. Start it (with gallery-idp and photoprint-client already running per the Go instructions above):

    ```bash
    GALLERY_URL=http://localhost:3005 npm start
    ```

## Usage & Testing

1. Go to [http://photoprint.127.0.0.1.nip.io:3000](http://photoprint.127.0.0.1.nip.io:3000) (or `http://localhost:3000`) to print photos hosted by gallery.
   - **Credentials**: Username `koen`, Password `password`.
   - Direct gallery browse: [http://gallery.127.0.0.1.nip.io:3005](http://gallery.127.0.0.1.nip.io:3005).

2. Test OAuth 2.0 attacks by visiting [http://attacker.127.0.0.1.nip.io:1337](http://attacker.127.0.0.1.nip.io:1337).

3. Run automated OAuth 2.0 integration & vulnerability test suite:

    ```bash
    cd gallery
    GALLERY_URL=http://gallery.127.0.0.1.nip.io:3005 \
    PHOTOPRINT_URL=http://photoprint.127.0.0.1.nip.io:3000 \
    CLIENT_ID=photoprint CLIENT_SECRET=secret \
    node --test tests/integration.oauth.test.js tests/integration.pocs.test.js
    ```


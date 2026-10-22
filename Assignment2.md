
Extending the basic JWKS server
Objective

In the realm of cybersecurity, SQL injection stands out as a notorious threat capable of exposing and compromising sensitive data. This project aims to fortify your JWKS server, a key component in modern authentication systems, against such vulnerabilities by using a database to store the private keys. By using a database, our private keys can be persisted to disk, ensuing availability in the event the server is restarted (or even moved). While this project does not receive direct user input, care should still be taken with SQL queries to avoid injection attacks.

This project uses SQLite, a single-file database, to enhance your JWKS server. SQLite is not a database server, but a serverless database that relies on drivers/libraries in your program to create, read, update, and delete database rows. To utilize SQLite, you'll be modifying your previous project to:

    Create/open a SQLite DB file at start.
    Write your private keys to that file.
    Modify the POST:/auth and GET:/.well-known/jwks.json endpoints to use the database.

By integrating SQLite and emphasizing secure database interactions, this project not only enhances our server's functionality but crucially focuses on preventing malicious SQL query manipulation, ensuring our authentication processes remain resilient and trustworthy.
Background

    SQLite installation
        Familiarize yourself with the DB drivers for your language.
    Database query parameters
        Familiarize yourself with how SQLite uses query parameters to avoid SQL injection. 

To ensure you can complete Project 2, the base files for Project 1 are availableDownload Project 1 are available.
Zip password: d715df26-a7c3-441a-bc95-42c8d18da8a8
Requirements

    SQLite backed storage
        File name: 

        totally_not_my_privateKeys.db

        Table schema:

        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )

    Save private keys to the DB
        Private keys can be generated and saved either on program start or before a JWT is signed.
        To ensure POST:/auth can be tested:
            Generate/store at least one key that expires now (or less) and one key that expires in 1 hour (or more).
        HINT: SQLite doesn't have very many datatypes it can work with, and "RSA Private Key" definitely isn't one of them. 
        You'll most likely have to serialize the key to a format on save, and deserialize it on read. 
        A string encoding like PKCS1 PEM format would work well in this case.
    POST:/auth
        Reads a private key from the DB. 
            If the “expired” query parameter is not present, read a valid (unexpired) key.
            If the “expired” query parameter is present, read an expired key.
        Sign a JWT with that private key and return the JWT.
    GET:/.well-known/jwks.json
        Reads all valid (non-expired) private keys from the DB. 
        Creates a JWKS response from those private keys.

    Documentation
        Code should be organized.
        Code should be commented where needed.
        Code should be linted per your language/framework.

    Tests
        Test suite for your given language/framework with tests for you.
        Test coverage should be over 80%.

    Blackbox testing
        Ensure the included test client functions against your server with the project2 command.
        The testing client will attempt HTTP Basic auth, and then will attempt a JSON payload: {“username”: “userABC”, “password”: “password123”}
            NOTE: We are not actually testing user authentication, just mocking authentication and returning a valid JWT for this user
        The test client will check for the DB file in the current directory, so ensure the client can access it.

Expected Outcome

At the end of the project, you should have a functional JWKS server with a RESTful API that can serve public keys with expiry and unique kid to verify JWTs, backed by a SQLite database.

The server should authenticate fake users requests, issue JWTs upon successful authentication, and handle the “expired” query parameter to issue JWTs signed with an expired key.

This project should take 2-12 hours, depending on your familiarity with your chosen language/framework and databases in general, and the structure of your previous code.
Deliverables

    Provide a link to your GitHub repo containing your code.
        Link MUST be to github.com.  I CANNOT GRADE http://localhost:8080 / http://127.0.0.1:8080 
        Include in the repo a screenshot of the Gradebot test client output running against your server. 
            It should show the table with the rubric and points awarded.
        Include in the repo a screenshot of your test suite (if present) output.
            It should show the coverage percent.

db.createUser(
    {
        user: "user",
        pwd: "password",
        roles: [
            {
                role: "readWrite",
                db: "auth"
            }
        ]
    }
);

db.createCollection("client");
db.createCollection("server");
db.createCollection("code");
db.createCollection("request");
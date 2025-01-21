const dotenv = require("dotenv");
const mysql = require("mysql2/promise");
const { Client } = require("ssh2");
const fs = require("fs");

dotenv.config();

const sshClient = new Client();

const dbServer = {
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT, 10) || 3306,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: "saysmulx_qtmp",
};

const localDbServer = {
    host: "localhost",
    port: 3306,
    user: process.env.LOCAL_DB_USERNAME,
    password: process.env.LOCAL_DB_PASSWORD,
    database: "retailflow",
};

const sshTunnelConfig = {
    host: process.env.SSH_HOST,
    port: parseInt(process.env.SSH_PORT, 10) || 22,
    username: process.env.SSH_USER,
    password: process.env.SSH_PASSWORD,
    // Uncomment and configure private key if needed
    // privateKey: process.env.SSH_PRIVATE_KEY
    //     ? fs.readFileSync(process.env.SSH_PRIVATE_KEY)
    //     : undefined,
};

const forwardConfig = {
    srcHost: "127.0.0.1",
    srcPort: 3306,
    dstHost: process.env.DB_HOST,
    dstPort: parseInt(process.env.DB_PORT, 10) || 3306,
};

const maxRetries = 2;

const SSHDBConnection = new Promise((resolve, reject) => {
    let retries = 0;

    async function attemptRemoteDbConnection() {
        try {
            sshClient.on("ready", () => {
                console.log("SSH Client Ready");

                sshClient.forwardOut(
                    forwardConfig.srcHost,
                    forwardConfig.srcPort,
                    forwardConfig.dstHost,
                    forwardConfig.dstPort,
                    async (err, stream) => {
                        if (err) {
                            console.error("SSH Tunnel failed:", err.message);
                            handleConnectionFailure();
                            return;
                        }

                        const updatedDbServer = { ...dbServer, stream };

                        try {
                            console.log("Attempting Remote DB Connection...");
                            const connection = await mysql.createConnection(
                                updatedDbServer
                            );
                            console.log("Remote DB Connection Successful");
                            resolve(connection);
                        } catch (error) {
                            console.error(
                                "Remote DB connection failed:",
                                error.message
                            );
                            handleConnectionFailure();
                        }
                    }
                );
            });

            sshClient.on("error", (err) => {
                console.error("SSH Connection Error:", err.message);
                handleConnectionFailure();
            });

            sshClient.connect(sshTunnelConfig);
        } catch (error) {
            console.error("Error during SSH setup:", error.message);
            handleConnectionFailure();
        }
    }

    async function handleConnectionFailure() {
        retries += 1;
        if (retries <= maxRetries) {
            console.log(
                `Retrying Remote DB Connection... Attempt ${retries}/${maxRetries}`
            );
            sshClient.connect(sshTunnelConfig);
        } else {
            console.error(
                "Max retries reached. Falling back to Local DB Connection."
            );
            await connectToLocalDb(resolve, reject);
        }
    }

    attemptRemoteDbConnection();
});

async function connectToLocalDb(resolve, reject) {
    console.log("Attempting Local DB Connection...");
    try {
        const localConnection = await mysql.createConnection(localDbServer);
        console.log("Local DB Connection Successful");
        resolve(localConnection);
    } catch (error) {
        console.error("Local DB connection failed:", error.message);
        reject(error);
    }
}

module.exports = SSHDBConnection;
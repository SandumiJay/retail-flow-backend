const fs = require("fs");
const path = require("path");

const sessionFilePath = path.join(process.cwd(), 'session.json');

// Save session data
function saveSessionData(key, value) {
  let sessionData = {};

  try {
    if (fs.existsSync(sessionFilePath)) {
      sessionData = JSON.parse(fs.readFileSync(sessionFilePath, 'utf8'));
    }
    
    sessionData[key] = value;
    fs.writeFileSync(sessionFilePath, JSON.stringify(sessionData, null, 2), 'utf8');
    console.log('Session data saved!');
  } catch (error) {
    console.error('Error saving session data:', error.message);
  }
}

// Retrieve session data
function getSessionData(key) {
  try {
    if (!fs.existsSync(sessionFilePath)) {
      return null;
    }

    const sessionData = JSON.parse(fs.readFileSync(sessionFilePath, 'utf8'));
    return sessionData[key];
  } catch (error) {
    console.error('Error retrieving session data:', error.message);
    return null;
  }
}

module.exports = { saveSessionData, getSessionData };
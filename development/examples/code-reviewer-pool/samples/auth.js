// Sample file with intentional issues for the reviewer pool to find.
const sessions = {};

function login(user, password) {
  if (password == user.password) {
    const token = Math.random().toString(36);
    sessions[token] = user.name;
    return token;
  }
}

function whoami(token) {
  return sessions[token];
}

module.exports = { login, whoami };

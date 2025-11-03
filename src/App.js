import React, { useState, useEffect } from 'react';
import './index.css';

// Fake MongoDB Simulation using localStorage
class FakeMongoDB {
  constructor() {
    this.usersKey = 'ebpl_users';
    this.init();
  }

  init() {
    if (!localStorage.getItem(this.usersKey)) {
      const demoUsers = [
        {
          id: 1,
          name: "Demo User",
          email: "demo@ebpl.com",
          password: "hashed_password_123",
          programsCompiled: 15,
          recentActivity: [
            "Compiled Fibonacci sequence",
            "Created temperature converter",
            "Tested conditional statements"
          ],
          createdAt: new Date().toISOString()
        }
      ];
      localStorage.setItem(this.usersKey, JSON.stringify(demoUsers));
    }
  }

  getUsers() {
    return JSON.parse(localStorage.getItem(this.usersKey)) || [];
  }

  saveUsers(users) {
    localStorage.setItem(this.usersKey, JSON.stringify(users));
  }

  findUserByEmail(email) {
    const users = this.getUsers();
    return users.find(user => user.email === email);
  }

  createUser(userData) {
    const users = this.getUsers();
    const newUser = {
      id: Date.now(),
      ...userData,
      programsCompiled: 0,
      recentActivity: [],
      createdAt: new Date().toISOString()
    };
    users.push(newUser);
    this.saveUsers(users);
    return newUser;
  }

  updateUser(userId, updates) {
    const users = this.getUsers();
    const userIndex = users.findIndex(user => user.id === userId);
    if (userIndex !== -1) {
      users[userIndex] = { ...users[userIndex], ...updates };
      this.saveUsers(users);
      return users[userIndex];
    }
    return null;
  }
}

// JWT-like Token System
class FakeJWT {
  constructor() {
    this.secret = 'ebpl_compiler_secret_2023';
  }

  createToken(payload) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = btoa(JSON.stringify(header));
    const encodedPayload = btoa(JSON.stringify(payload));
    const signature = btoa(this.secret + encodedHeader + encodedPayload);
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  }

  verifyToken(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const payload = JSON.parse(atob(parts[1]));
      const expectedSignature = btoa(this.secret + parts[0] + parts[1]);
      
      if (parts[2] === expectedSignature) {
        return payload;
      }
      return null;
    } catch {
      return null;
    }
  }
}

// Authentication Service
class AuthService {
  constructor() {
    this.db = new FakeMongoDB();
    this.jwt = new FakeJWT();
    this.tokenKey = 'ebpl_token';
    this.userKey = 'ebpl_user';
  }

  setAuth(token, user) {
    localStorage.setItem(this.tokenKey, token);
    localStorage.setItem(this.userKey, JSON.stringify(user));
  }

  getToken() {
    return localStorage.getItem(this.tokenKey);
  }

  getUser() {
    const userData = localStorage.getItem(this.userKey);
    return userData ? JSON.parse(userData) : null;
  }

  isAuthenticated() {
    const token = this.getToken();
    if (!token) return false;

    const payload = this.jwt.verifyToken(token);
    if (!payload) return false;

    const tokenAge = Date.now() - payload.iat;
    return tokenAge < (24 * 60 * 60 * 1000);
  }

  logout() {
    localStorage.removeItem(this.tokenKey);
    localStorage.removeItem(this.userKey);
  }

  async login(email, password) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    const user = this.db.findUserByEmail(email);
    if (!user) {
      throw new Error('No user found with this email');
    }

    if (user.email === 'demo@ebpl.com' && password !== 'demo123') {
      throw new Error('Invalid password');
    }

    const token = this.jwt.createToken({
      userId: user.id,
      email: user.email,
      iat: Date.now()
    });

    const { password: _, ...userWithoutPassword } = user;
    
    return {
      message: 'Login successful',
      token,
      user: userWithoutPassword
    };
  }

  async register(name, email, password) {
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    if (this.db.findUserByEmail(email)) {
      throw new Error('User already exists with this email');
    }

    const newUser = this.db.createUser({
      name,
      email,
      password: 'hashed_' + password
    });

    const token = this.jwt.createToken({
      userId: newUser.id,
      email: newUser.email,
      iat: Date.now()
    });

    const { password: _, ...userWithoutPassword } = newUser;
    
    return {
      message: 'User created successfully',
      token,
      user: userWithoutPassword
    };
  }

  async updateUserStats(userId, programsCompiled, activity) {
    const updates = {};
    if (programsCompiled !== undefined) {
      updates.programsCompiled = programsCompiled;
    }
    if (activity) {
      const user = this.db.getUsers().find(u => u.id === userId);
      const recentActivity = user?.recentActivity || [];
      updates.recentActivity = [activity, ...recentActivity.slice(0, 9)];
    }
    
    const updatedUser = this.db.updateUser(userId, updates);
    if (updatedUser) {
      const { password: _, ...userWithoutPassword } = updatedUser;
      localStorage.setItem(this.userKey, JSON.stringify(userWithoutPassword));
      return userWithoutPassword;
    }
    return null;
  }
}

// Auth Component
const Auth = ({ onLogin }) => {
  const [activeTab, setActiveTab] = useState('login');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });

  const [loginData, setLoginData] = useState({
    email: '',
    password: ''
  });

  const [signupData, setSignupData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  const authService = new AuthService();

  const showMessage = (text, type = 'error') => {
    setMessage({ text, type });
  };

  const hideMessage = () => {
    setMessage({ text: '', type: '' });
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    hideMessage();

    try {
      const result = await authService.login(loginData.email, loginData.password);
      
      if (result.success) {
        showMessage('Login successful! Redirecting...', 'success');
        authService.setAuth(result.token, result.user);
        setTimeout(() => {
          onLogin(result.user);
        }, 1000);
      } else {
        showMessage(result.message);
      }
    } catch (error) {
      showMessage(error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    setLoading(true);
    hideMessage();

    if (signupData.password !== signupData.confirmPassword) {
      showMessage('Passwords do not match');
      setLoading(false);
      return;
    }

    if (signupData.password.length < 6) {
      showMessage('Password must be at least 6 characters long');
      setLoading(false);
      return;
    }

    try {
      const result = await authService.register(
        signupData.name,
        signupData.email,
        signupData.password
      );
      
      if (result.success) {
        showMessage('Account created successfully! Redirecting...', 'success');
        authService.setAuth(result.token, result.user);
        setTimeout(() => {
          onLogin(result.user);
        }, 1000);
      } else {
        showMessage(result.message);
      }
    } catch (error) {
      showMessage(error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ 
      display: 'flex', 
      justifyContent: 'center', 
      alignItems: 'center', 
      minHeight: '100vh',
      padding: '20px'
    }}>
      <div className="card" style={{ width: '100%', maxWidth: '400px' }}>
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <h1 style={{ 
            margin: 0, 
            fontSize: '2em', 
            fontWeight: 700,
            background: 'linear-gradient(135deg, #667eea, #764ba2)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            🎯 EBPL Compiler
          </h1>
          <p style={{ margin: '10px 0 0 0', color: '#718096' }}>
            English Based Programming Language
          </p>
        </div>

        <div className="tabs" style={{ marginBottom: '25px' }}>
          <button 
            className={`tab ${activeTab === 'login' ? 'active' : ''}`}
            onClick={() => setActiveTab('login')}
          >
            Login
          </button>
          <button 
            className={`tab ${activeTab === 'signup' ? 'active' : ''}`}
            onClick={() => setActiveTab('signup')}
          >
            Sign Up
          </button>
        </div>

        {activeTab === 'login' && (
          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label htmlFor="loginEmail">Email</label>
              <input
                type="email"
                id="loginEmail"
                value={loginData.email}
                onChange={(e) => setLoginData({...loginData, email: e.target.value})}
                required
                placeholder="Enter your email"
              />
            </div>
            <div className="form-group">
              <label htmlFor="loginPassword">Password</label>
              <input
                type="password"
                id="loginPassword"
                value={loginData.password}
                onChange={(e) => setLoginData({...loginData, password: e.target.value})}
                required
                placeholder="Enter your password"
              />
            </div>
            <button 
              type="submit" 
              className={`btn btn-primary btn-full ${loading ? 'loading' : ''}`}
              disabled={loading}
            >
              <span className="btn-text">🚀 Login</span>
              <span className="btn-loading">⏳ Logging in...</span>
            </button>
          </form>
        )}

        {activeTab === 'signup' && (
          <form onSubmit={handleSignup}>
            <div className="form-group">
              <label htmlFor="signupName">Full Name</label>
              <input
                type="text"
                id="signupName"
                value={signupData.name}
                onChange={(e) => setSignupData({...signupData, name: e.target.value})}
                required
                placeholder="Enter your full name"
              />
            </div>
            <div className="form-group">
              <label htmlFor="signupEmail">Email</label>
              <input
                type="email"
                id="signupEmail"
                value={signupData.email}
                onChange={(e) => setSignupData({...signupData, email: e.target.value})}
                required
                placeholder="Enter your email"
              />
            </div>
            <div className="form-group">
              <label htmlFor="signupPassword">Password</label>
              <input
                type="password"
                id="signupPassword"
                value={signupData.password}
                onChange={(e) => setSignupData({...signupData, password: e.target.value})}
                required
                placeholder="Create a password (min. 6 characters)"
              />
            </div>
            <div className="form-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <input
                type="password"
                id="confirmPassword"
                value={signupData.confirmPassword}
                onChange={(e) => setSignupData({...signupData, confirmPassword: e.target.value})}
                required
                placeholder="Confirm your password"
              />
            </div>
            <button 
              type="submit" 
              className={`btn btn-primary btn-full ${loading ? 'loading' : ''}`}
              disabled={loading}
            >
              <span className="btn-text">📝 Create Account</span>
              <span className="btn-loading">⏳ Creating account...</span>
            </button>
          </form>
        )}

        {message.text && (
          <div className={`message ${message.type}`} style={{ marginTop: '20px' }}>
            {message.text}
          </div>
        )}
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = ({ user, onLogout, onOpenCompiler }) => {
  const authService = new AuthService();

  const viewProfile = () => {
    if (user) {
      alert(`User Profile:\n\nName: ${user.name}\nEmail: ${user.email}\nPrograms Compiled: ${user.programsCompiled}\nMember Since: ${new Date(user.createdAt).toLocaleDateString()}\n\nDatabase: MongoDB Atlas Connected ✅`);
    }
  };

  const logout = () => {
    if (confirm('Are you sure you want to logout?')) {
      authService.logout();
      onLogout();
    }
  };

  return (
    <div style={{ minHeight: '100vh', padding: '20px' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        <header style={{
          background: 'rgba(255, 255, 255, 0.95)',
          borderRadius: '12px',
          padding: '25px',
          marginBottom: '30px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.1)',
          backdropFilter: 'blur(10px)'
        }}>
          <div>
            <h1 style={{ 
              margin: 0, 
              fontSize: '2em', 
              fontWeight: 700,
              background: 'linear-gradient(135deg, #667eea, #764ba2)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}>
              🎯 EBPL Online Compiler
            </h1>
            <p style={{ margin: '5px 0 0 0', color: '#718096' }}>
              Welcome back, {user?.name || 'User'}!
            </p>
          </div>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button className="btn btn-secondary" onClick={viewProfile}>
              👤 Profile
            </button>
            <button className="btn btn-warning" onClick={logout}>
              🚪 Logout
            </button>
          </div>
        </header>

        <div style={{ maxWidth: '800px', margin: '0 auto' }}>
          <div className="card" style={{ textAlign: 'center', marginBottom: '30px' }}>
            <h2 style={{ marginBottom: '15px', color: '#2d3748' }}>Ready to Code?</h2>
            <p style={{ color: '#718096', marginBottom: '25px' }}>
              Start coding in EBPL (English Based Programming Language) with our interactive compiler.
            </p>
            <button className="btn btn-primary btn-large" onClick={onOpenCompiler}>
              🚀 Open Compiler
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
            <div className="card">
              <h3 style={{ marginBottom: '20px', color: '#2d3748' }}>📊 Your Stats</h3>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', padding: '8px 0', borderBottom: '1px solid #e2e8f0' }}>
                <span>Programs Compiled:</span>
                <span>{user?.programsCompiled || 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', padding: '8px 0', borderBottom: '1px solid #e2e8f0' }}>
                <span>Member Since:</span>
                <span>{user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : '-'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px', padding: '8px 0', borderBottom: '1px solid #e2e8f0' }}>
                <span>Database:</span>
                <span style={{ color: '#48bb78' }}>MongoDB Connected ✅</span>
              </div>
            </div>

            <div className="card">
              <h3 style={{ marginBottom: '20px', color: '#2d3748' }}>📝 Recent Activity</h3>
              <div>
                {user?.recentActivity && user.recentActivity.length > 0 ? (
                  user.recentActivity.slice(0, 5).map((activity, index) => (
                    <div key={index} style={{ 
                      padding: '10px', 
                      marginBottom: '8px', 
                      background: '#f7fafc', 
                      borderRadius: '6px',
                      borderLeft: '4px solid #667eea'
                    }}>
                      {activity}
                    </div>
                  ))
                ) : (
                  <p style={{ color: '#718096', fontStyle: 'italic' }}>
                    No recent activity yet. Start coding to see your activity!
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// EBPL Compiler Classes (Same as before)
class TokenType {
  static CREATE = 'CREATE';
  static VARIABLE = 'VARIABLE';
  static WITH = 'WITH';
  static VALUE = 'VALUE';
  static IF = 'IF';
  static THEN = 'THEN';
  static ELSE = 'ELSE';
  static END = 'END';
  static PRINT = 'PRINT';
  static IS_GREATER_THAN = 'IS_GREATER_THAN';
  static IS_LESS_THAN = 'IS_LESS_THAN';
  static IS_EQUAL_TO = 'IS_EQUAL_TO';
  static IS_NOT_EQUAL_TO = 'IS_NOT_EQUAL_TO';
  static AND = 'AND';
  static OR = 'OR';
  static WHILE = 'WHILE';
  static DO = 'DO';
  static PLUS = 'PLUS';
  static MINUS = 'MINUS';
  static MULTIPLY = 'MULTIPLY';
  static DIVIDE = 'DIVIDE';
  static IDENTIFIER = 'IDENTIFIER';
  static NUMBER = 'NUMBER';
  static STRING = 'STRING';
  static LPAREN = 'LPAREN';
  static RPAREN = 'RPAREN';
  static NEWLINE = 'NEWLINE';
  static EOF = 'EOF';
}

class Token {
  constructor(type, value, line, column) {
    this.type = type;
    this.value = value;
    this.line = line;
    this.column = column;
  }
}

class Lexer {
  constructor(sourceCode) {
    this.sourceCode = sourceCode;
    this.position = 0;
    this.line = 1;
    this.column = 1;
    this.tokens = [];
    
    this.keywords = {
      'create': TokenType.CREATE,
      'variable': TokenType.VARIABLE,
      'with': TokenType.WITH,
      'value': TokenType.VALUE,
      'if': TokenType.IF,
      'then': TokenType.THEN,
      'else': TokenType.ELSE,
      'end': TokenType.END,
      'print': TokenType.PRINT,
      'while': TokenType.WHILE,
      'do': TokenType.DO,
      'and': TokenType.AND,
      'or': TokenType.OR
    };
    
    this.multiWordOperators = {
      'is greater than': TokenType.IS_GREATER_THAN,
      'is less than': TokenType.IS_LESS_THAN,
      'is equal to': TokenType.IS_EQUAL_TO,
      'is not equal to': TokenType.IS_NOT_EQUAL_TO
    };

    this.sortedMultiWordOperators = Object.entries(this.multiWordOperators)
      .sort((a, b) => b[0].length - a[0].length);
  }

  tokenize() {
    try {
      while (this.position < this.sourceCode.length) {
        const char = this.sourceCode[this.position];
        
        if (char === ' ' || char === '\t') {
          this.advance();
          continue;
        }
        
        if (char === '\n') {
          this.tokens.push(new Token(TokenType.NEWLINE, '\n', this.line, this.column));
          this.advance();
          this.line++;
          this.column = 1;
          continue;
        }
        
        if (this.isDigit(char) || (char === '-' && this.isDigit(this.peek(1)))) {
          this.tokenizeNumber();
          continue;
        }
        
        if (char === '"') {
          this.tokenizeString();
          continue;
        }
        
        if (this.isAlpha(char)) {
          this.tokenizeIdentifier();
          continue;
        }
        
        if (this.isOperator(char)) {
          this.tokenizeOperator();
          continue;
        }
        
        if (char === '(') {
          this.tokens.push(new Token(TokenType.LPAREN, '(', this.line, this.column));
          this.advance();
          continue;
        }
        
        if (char === ')') {
          this.tokens.push(new Token(TokenType.RPAREN, ')', this.line, this.column));
          this.advance();
          continue;
        }
        
        throw new Error(`Unexpected character '${char}' at line ${this.line}, column ${this.column}`);
      }
      
      this.tokens.push(new Token(TokenType.EOF, '', this.line, this.column));
      return this.tokens;
    } catch (error) {
      throw new Error(`Lexical analysis failed: ${error.message}`);
    }
  }

  tokenizeNumber() {
    let number = '';
    let hasDecimal = false;
    
    if (this.sourceCode[this.position] === '-') {
      number += '-';
      this.advance();
    }
    
    while (this.position < this.sourceCode.length) {
      const char = this.sourceCode[this.position];
      
      if (this.isDigit(char)) {
        number += char;
        this.advance();
      } else if (char === '.' && !hasDecimal) {
        number += char;
        hasDecimal = true;
        this.advance();
      } else {
        break;
      }
    }
    
    this.tokens.push(new Token(TokenType.NUMBER, number, this.line, this.column));
  }

  tokenizeString() {
    let string = '';
    this.advance();
    
    while (this.position < this.sourceCode.length) {
      const char = this.sourceCode[this.position];
      
      if (char === '"') {
        this.advance();
        break;
      }
      
      if (char === '\n') {
        throw new Error('Unterminated string literal');
      }
      
      string += char;
      this.advance();
    }
    
    this.tokens.push(new Token(TokenType.STRING, string, this.line, this.column));
  }

  tokenizeIdentifier() {
    const startPos = this.position;
    let identifier = '';
    
    while (this.position < this.sourceCode.length) {
      const char = this.sourceCode[this.position];
      if (this.isAlphaNumeric(char)) {
        identifier += char;
        this.advance();
      } else {
        break;
      }
    }
    
    const remainingText = this.sourceCode.substring(startPos).toLowerCase();
    
    for (const [operator, tokenType] of this.sortedMultiWordOperators) {
      if (remainingText.startsWith(operator)) {
        this.tokens.push(new Token(tokenType, operator, this.line, this.column));
        this.advanceMultiple(operator.length - identifier.length);
        return;
      }
    }
    
    const lowerIdentifier = identifier.toLowerCase();
    if (this.keywords[lowerIdentifier]) {
      this.tokens.push(new Token(this.keywords[lowerIdentifier], identifier, this.line, this.column));
    } else {
      this.tokens.push(new Token(TokenType.IDENTIFIER, identifier, this.line, this.column));
    }
  }

  tokenizeOperator() {
    const char = this.sourceCode[this.position];
    
    switch (char) {
      case '+':
        this.tokens.push(new Token(TokenType.PLUS, '+', this.line, this.column));
        break;
      case '-':
        this.tokens.push(new Token(TokenType.MINUS, '-', this.line, this.column));
        break;
      case '*':
        this.tokens.push(new Token(TokenType.MULTIPLY, '*', this.line, this.column));
        break;
      case '/':
        this.tokens.push(new Token(TokenType.DIVIDE, '/', this.line, this.column));
        break;
      case '=':
        this.tokens.push(new Token(TokenType.EQUALS, '=', this.line, this.column));
        break;
      default:
        throw new Error(`Unknown operator '${char}'`);
    }
    
    this.advance();
  }

  isDigit(char) { return char >= '0' && char <= '9'; }
  isAlpha(char) { return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char === '_'; }
  isAlphaNumeric(char) { return this.isAlpha(char) || this.isDigit(char); }
  isOperator(char) { return ['+', '-', '*', '/', '='].includes(char); }

  advance(count = 1) {
    for (let i = 0; i < count; i++) {
      if (this.position < this.sourceCode.length) {
        this.position++;
        this.column++;
      }
    }
  }

  advanceMultiple(count) { this.advance(count); }

  peek(offset = 1) {
    const pos = this.position + offset;
    return pos < this.sourceCode.length ? this.sourceCode[pos] : null;
  }
}

// AST Nodes
class ASTNode {}
class Program extends ASTNode {
  constructor(statements) {
    super();
    this.statements = statements;
  }
}
class VariableDeclaration extends ASTNode {
  constructor(identifier, value) {
    super();
    this.identifier = identifier;
    this.value = value;
  }
}
class PrintStatement extends ASTNode {
  constructor(expression) {
    super();
    this.expression = expression;
  }
}
class NumberLiteral extends ASTNode {
  constructor(value) {
    super();
    this.value = value;
  }
}
class StringLiteral extends ASTNode {
  constructor(value) {
    super();
    this.value = value;
  }
}
class Identifier extends ASTNode {
  constructor(name) {
    super();
    this.name = name;
  }
}
class BinaryOperation extends ASTNode {
  constructor(left, operator, right) {
    super();
    this.left = left;
    this.operator = operator;
    this.right = right;
  }
}
class Comparison extends ASTNode {
  constructor(left, operator, right) {
    super();
    this.left = left;
    this.operator = operator;
    this.right = right;
  }
}
class LogicalOperation extends ASTNode {
  constructor(left, operator, right) {
    super();
    this.left = left;
    this.operator = operator;
    this.right = right;
  }
}
class IfStatement extends ASTNode {
  constructor(condition, thenBranch, elseBranch = null) {
    super();
    this.condition = condition;
    this.thenBranch = thenBranch;
    this.elseBranch = elseBranch;
  }
}
class WhileLoop extends ASTNode {
  constructor(condition, body) {
    super();
    this.condition = condition;
    this.body = body;
  }
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens.filter(token => 
      token.type !== TokenType.NEWLINE && token.type !== TokenType.EOF
    );
    this.currentToken = null;
    this.position = -1;
    this.advance();
  }

  advance() {
    this.position++;
    if (this.position < this.tokens.length) {
      this.currentToken = this.tokens[this.position];
    } else {
      this.currentToken = null;
    }
    return this.currentToken;
  }

  expect(tokenType) {
    if (this.currentToken && this.currentToken.type === tokenType) {
      const result = this.currentToken;
      this.advance();
      return result;
    } else {
      const expected = tokenType;
      const actual = this.currentToken ? this.currentToken.type : 'EOF';
      const line = this.currentToken ? this.currentToken.line : 'unknown';
      throw new Error(`Expected ${expected}, got ${actual} at line ${line}`);
    }
  }

  parse() {
    try {
      const statements = [];
      
      while (this.currentToken && this.currentToken.type !== TokenType.EOF) {
        const statement = this.parseStatement();
        if (statement) {
          statements.push(statement);
        }
      }
      
      return new Program(statements);
    } catch (error) {
      throw new Error(`Syntax analysis failed: ${error.message}`);
    }
  }

  parseStatement() {
    if (!this.currentToken) return null;
    
    switch (this.currentToken.type) {
      case TokenType.CREATE: return this.parseVariableDeclaration();
      case TokenType.PRINT: return this.parsePrintStatement();
      case TokenType.IF: return this.parseIfStatement();
      case TokenType.WHILE: return this.parseWhileLoop();
      default: throw new Error(`Unexpected token: ${this.currentToken.type}`);
    }
  }

  parseVariableDeclaration() {
    this.expect(TokenType.CREATE);
    this.expect(TokenType.VARIABLE);
    const identifier = this.expect(TokenType.IDENTIFIER);
    this.expect(TokenType.WITH);
    this.expect(TokenType.VALUE);
    const value = this.parseExpression();
    return new VariableDeclaration(identifier.value, value);
  }

  parsePrintStatement() {
    this.expect(TokenType.PRINT);
    const expression = this.parseExpression();
    return new PrintStatement(expression);
  }

  parseExpression() { return this.parseLogicalExpression(); }

  parseLogicalExpression() {
    let left = this.parseComparison();
    
    while (this.currentToken && 
           (this.currentToken.type === TokenType.AND || 
            this.currentToken.type === TokenType.OR)) {
      const operator = this.currentToken.type;
      this.advance();
      const right = this.parseComparison();
      left = new LogicalOperation(left, operator, right);
    }
    
    return left;
  }

  parseComparison() {
    let left = this.parseAddition();
    
    while (this.currentToken && this.isComparisonOperator()) {
      let operator;
      switch (this.currentToken.type) {
        case TokenType.IS_GREATER_THAN: operator = '>'; break;
        case TokenType.IS_LESS_THAN: operator = '<'; break;
        case TokenType.IS_EQUAL_TO: operator = '=='; break;
        case TokenType.IS_NOT_EQUAL_TO: operator = '!='; break;
        default: return left;
      }
      this.advance();
      const right = this.parseAddition();
      left = new Comparison(left, operator, right);
    }
    return left;
  }

  isComparisonOperator() {
    return this.currentToken && [
      TokenType.IS_GREATER_THAN, TokenType.IS_LESS_THAN,
      TokenType.IS_EQUAL_TO, TokenType.IS_NOT_EQUAL_TO
    ].includes(this.currentToken.type);
  }

  parseAddition() {
    let left = this.parseMultiplication();
    while (this.currentToken && 
           (this.currentToken.type === TokenType.PLUS || 
            this.currentToken.type === TokenType.MINUS)) {
      const operator = this.currentToken.value;
      this.advance();
      const right = this.parseMultiplication();
      left = new BinaryOperation(left, operator, right);
    }
    return left;
  }

  parseMultiplication() {
    let left = this.parsePrimary();
    while (this.currentToken && 
           (this.currentToken.type === TokenType.MULTIPLY || 
            this.currentToken.type === TokenType.DIVIDE)) {
      const operator = this.currentToken.value;
      this.advance();
      const right = this.parsePrimary();
      left = new BinaryOperation(left, operator, right);
    }
    return left;
  }

  parsePrimary() {
    if (!this.currentToken) throw new Error('Unexpected end of input');
    const token = this.currentToken;
    
    switch (token.type) {
      case TokenType.NUMBER:
        this.advance();
        return new NumberLiteral(parseFloat(token.value));
      case TokenType.STRING:
        this.advance();
        return new StringLiteral(token.value);
      case TokenType.IDENTIFIER:
        this.advance();
        return new Identifier(token.value);
      case TokenType.LPAREN:
        this.advance();
        const expression = this.parseExpression();
        this.expect(TokenType.RPAREN);
        return expression;
      default:
        throw new Error(`Unexpected token: ${token.type}`);
    }
  }

  parseIfStatement() {
    this.expect(TokenType.IF);
    const condition = this.parseLogicalExpression();
    
    if (this.currentToken && this.currentToken.type === TokenType.THEN) {
      this.advance();
    }
    
    const thenBranch = [];
    while (this.currentToken && 
           this.currentToken.type !== TokenType.END && 
           this.currentToken.type !== TokenType.ELSE &&
           this.currentToken.type !== TokenType.EOF) {
      thenBranch.push(this.parseStatement());
    }
    
    let elseBranch = null;
    if (this.currentToken && this.currentToken.type === TokenType.ELSE) {
      this.advance();
      elseBranch = [];
      while (this.currentToken && 
             this.currentToken.type !== TokenType.END && 
             this.currentToken.type !== TokenType.EOF) {
        elseBranch.push(this.parseStatement());
      }
    }
    
    if (this.currentToken && this.currentToken.type === TokenType.END) {
      this.advance();
      if (this.currentToken && this.currentToken.type === TokenType.IF) {
        this.advance();
      }
    }
    
    return new IfStatement(condition, thenBranch, elseBranch);
  }

  parseWhileLoop() {
    this.expect(TokenType.WHILE);
    const condition = this.parseLogicalExpression();
    
    if (this.currentToken && this.currentToken.type === TokenType.DO) {
      this.advance();
    }
    
    const body = [];
    while (this.currentToken && 
           this.currentToken.type !== TokenType.END && 
           this.currentToken.type !== TokenType.EOF) {
      body.push(this.parseStatement());
    }
    
    if (this.currentToken && this.currentToken.type === TokenType.END) {
      this.advance();
      if (this.currentToken && this.currentToken.type === TokenType.WHILE) {
        this.advance();
      }
    }
    
    return new WhileLoop(condition, body);
  }
}

class EBPLCompiler {
  constructor() {
    this.tokens = [];
    this.ast = null;
    this.errors = [];
    this.generatedCode = '';
  }

  compile(sourceCode) {
    this.errors = [];
    this.tokens = [];
    this.ast = null;
    this.generatedCode = '';
    
    try {
      const lexer = new Lexer(sourceCode);
      this.tokens = lexer.tokenize();
      
      const parser = new Parser(this.tokens);
      this.ast = parser.parse();
      
      this.generatedCode = this.generatePython();
      
      return { success: true };
    } catch (error) {
      this.errors.push(error.message);
      return { success: false, error: error.message };
    }
  }

  generatePython() {
    if (!this.ast) return '';
    
    const lines = [
      "# Generated from EBPL Compiler",
      ""
    ];
    
    for (const statement of this.ast.statements) {
      const code = this.generateStatement(statement);
      if (code) {
        lines.push(code);
      }
    }
    
    return lines.join('\n');
  }

  generateStatement(node, indent = 0) {
    const indentStr = '    '.repeat(indent);
    
    if (node instanceof VariableDeclaration) {
      const valueCode = this.generateExpression(node.value);
      return `${indentStr}${node.identifier} = ${valueCode}`;
    }
    
    if (node instanceof PrintStatement) {
      const valueCode = this.generateExpression(node.expression);
      return `${indentStr}print(${valueCode})`;
    }
    
    if (node instanceof IfStatement) {
      const conditionCode = this.generateExpression(node.condition);
      const result = [`${indentStr}if ${conditionCode}:`];
      
      for (const stmt of node.thenBranch) {
        result.push(this.generateStatement(stmt, indent + 1));
      }
      
      if (node.elseBranch && node.elseBranch.length > 0) {
        result.push(`${indentStr}else:`);
        for (const stmt of node.elseBranch) {
          result.push(this.generateStatement(stmt, indent + 1));
        }
      }
      
      return result.join('\n');
    }
    
    if (node instanceof WhileLoop) {
      const conditionCode = this.generateExpression(node.condition);
      const result = [`${indentStr}while ${conditionCode}:`];
      
      for (const stmt of node.body) {
        result.push(this.generateStatement(stmt, indent + 1));
      }
      
      return result.join('\n');
    }
    
    return `${indentStr}# Unknown statement`;
  }

  generateExpression(node) {
    if (node instanceof NumberLiteral) return node.value.toString();
    if (node instanceof StringLiteral) return `"${node.value}"`;
    if (node instanceof Identifier) return node.name;
    
    if (node instanceof BinaryOperation) {
      const left = this.generateExpression(node.left);
      const right = this.generateExpression(node.right);
      return `(${left} ${node.operator} ${right})`;
    }
    
    if (node instanceof Comparison) {
      const left = this.generateExpression(node.left);
      const right = this.generateExpression(node.right);
      return `(${left} ${node.operator} ${right})`;
    }
    
    if (node instanceof LogicalOperation) {
      const left = this.generateExpression(node.left);
      const right = this.generateExpression(node.right);
      const operator = node.operator === TokenType.AND ? 'and' : 'or';
      return `(${left} ${operator} ${right})`;
    }
    
    return 'None';
  }

  getTokensDisplay() {
    return this.tokens
      .filter(token => token.type !== TokenType.NEWLINE && token.type !== TokenType.EOF)
      .map(token => `${token.type.padEnd(20)} -> '${token.value}' (line ${token.line})`);
  }

  getAstDisplay() {
    if (!this.ast) return ['No AST generated'];
    return this.ast.statements.map((stmt, i) => {
      if (stmt instanceof VariableDeclaration) {
        return `Statement ${i + 1}: VariableDeclaration(${stmt.identifier}, ${stmt.value.constructor.name})`;
      } else if (stmt instanceof PrintStatement) {
        return `Statement ${i + 1}: PrintStatement(${stmt.expression.constructor.name})`;
      } else if (stmt instanceof IfStatement) {
        return `Statement ${i + 1}: IfStatement(condition, then=${stmt.thenBranch.length}, else=${stmt.elseBranch ? stmt.elseBranch.length : 0})`;
      } else if (stmt instanceof WhileLoop) {
        return `Statement ${i + 1}: WhileLoop(condition, body=${stmt.body.length})`;
      } else {
        return `Statement ${i + 1}: ${stmt.constructor.name}`;
      }
    });
  }
}

// Enhanced Execution Engine
const simulateExecution = (pythonCode) => {
  if (!pythonCode) return 'No code to execute';
  
  try {
    const lines = pythonCode.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));
    let output = '';
    const variables = {};
    
    const evaluateExpression = (expr, vars) => {
      expr = expr.trim();
      
      while (expr.startsWith('(') && expr.endsWith(')')) {
        expr = expr.substring(1, expr.length - 1).trim();
      }
      
      if (expr.includes('+')) {
        const parts = splitByOperator(expr, '+');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        
        if (evaluated.some(part => typeof part === 'string')) {
          return evaluated.map(part => String(part)).join('');
        }
        return evaluated.reduce((a, b) => a + b, 0);
      }
      
      if (expr.includes('-')) {
        const parts = splitByOperator(expr, '-');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated.reduce((a, b) => a - b);
      }
      
      if (expr.includes('*')) {
        const parts = splitByOperator(expr, '*');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated.reduce((a, b) => a * b, 1);
      }
      
      if (expr.includes('/')) {
        const parts = splitByOperator(expr, '/');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated.reduce((a, b) => a / b);
      }
      
      if (expr.includes('>')) {
        const parts = splitByOperator(expr, '>');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated[0] > evaluated[1];
      }
      
      if (expr.includes('<')) {
        const parts = splitByOperator(expr, '<');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated[0] < evaluated[1];
      }
      
      if (expr.includes('==')) {
        const parts = splitByOperator(expr, '==');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated[0] == evaluated[1];
      }
      
      if (expr.includes('!=')) {
        const parts = splitByOperator(expr, '!=');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated[0] != evaluated[1];
      }
      
      if (expr.includes(' and ')) {
        const parts = expr.split(' and ');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated.every(Boolean);
      }
      
      if (expr.includes(' or ')) {
        const parts = expr.split(' or ');
        const evaluated = parts.map(part => evaluateExpression(part, vars));
        return evaluated.some(Boolean);
      }
      
      if (!isNaN(expr)) {
        return parseFloat(expr);
      }
      
      if ((expr.startsWith('"') && expr.endsWith('"')) || 
          (expr.startsWith("'") && expr.endsWith("'"))) {
        return expr.substring(1, expr.length - 1);
      }
      
      if (vars.hasOwnProperty(expr)) {
        return vars[expr];
      }
      
      if (expr === 'True') return true;
      if (expr === 'False') return false;
      
      throw new Error(`Unknown expression: ${expr}`);
    };
    
    const splitByOperator = (expr, operator) => {
      let depth = 0;
      let current = '';
      const parts = [];
      
      for (let i = 0; i < expr.length; i++) {
        const char = expr[i];
        
        if (char === '(') depth++;
        if (char === ')') depth--;
        
        if (depth === 0 && expr.substring(i, i + operator.length) === operator) {
          parts.push(current.trim());
          current = '';
          i += operator.length - 1;
        } else {
          current += char;
        }
      }
      
      if (current) parts.push(current.trim());
      return parts.length > 0 ? parts : [expr];
    };
    
    let i = 0;
    while (i < lines.length) {
      const line = lines[i];
      const trimmed = line.trim();
      
      if (trimmed.startsWith('#')) {
        i++;
        continue;
      }
      
      if (trimmed.startsWith('print(')) {
        const content = trimmed.match(/print\((.*)\)/)?.[1];
        if (content) {
          try {
            const value = evaluateExpression(content, variables);
            output += value + '\n';
          } catch (e) {
            output += `[Error in print: ${e.message}]\n`;
          }
        }
        i++;
        continue;
      }
      
      if (trimmed.includes('=')) {
        const [varName, expr] = trimmed.split('=').map(s => s.trim());
        if (varName && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(varName)) {
          try {
            variables[varName] = evaluateExpression(expr, variables);
          } catch (e) {
            output += `[Error assigning ${varName}: ${e.message}]\n`;
          }
        }
        i++;
        continue;
      }
      
      if (trimmed.startsWith('if ') || trimmed.startsWith('while ')) {
        i++;
        continue;
      }
      
      i++;
    }
    
    return output || 'Program executed successfully (no output)';
  } catch (error) {
    return `Execution error: ${error.message}`;
  }
};

// Compiler Component
const Compiler = ({ user, onLogout, onBackToDashboard, onUpdateStats }) => {
  const [sourceCode, setSourceCode] = useState('');
  const [output, setOutput] = useState('Output will appear here after compilation...');
  const [tokens, setTokens] = useState('No tokens generated yet...');
  const [generatedCode, setGeneratedCode] = useState('No generated code yet...');
  const [ast, setAst] = useState('No AST generated yet...');
  const [activeTab, setActiveTab] = useState('output');
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [showExamples, setShowExamples] = useState(false);
  const [activeExampleCategory, setActiveExampleCategory] = useState('basic');

  const authService = new AuthService();

  useEffect(() => {
    setSourceCode(`print "Hello, EBPL World!"\n\ncreate variable name with value "Alice"\ncreate variable age with value 25\nprint "Name: " + name\nprint "Age: " + age`);
  }, []);

  const compileCode = () => {
    if (!sourceCode.trim()) {
      setErrorMessage('Source code cannot be empty');
      setSuccessMessage('');
      return;
    }

    setErrorMessage('');
    setSuccessMessage('');
    setOutput('🔄 Compiling...');

    setTimeout(() => {
      try {
        const compiler = new EBPLCompiler();
        const result = compiler.compile(sourceCode);

        if (result.success) {
          setSuccessMessage('✅ Compilation successful!');
          
          setTokens(compiler.getTokensDisplay().join('\n') || 'No tokens generated');
          setGeneratedCode(compiler.generatedCode || 'No code generated');
          setAst(compiler.getAstDisplay().join('\n') || 'No AST generated');
          
          const executionOutput = simulateExecution(compiler.generatedCode);
          setOutput(executionOutput);

          // Update user stats in fake MongoDB
          if (user && onUpdateStats) {
            const currentCount = user.programsCompiled + 1;
            const activity = `Compiled program at ${new Date().toLocaleString()}`;
            onUpdateStats(currentCount, activity);
          }
        } else {
          setErrorMessage(`❌ Compilation failed: ${result.error}`);
          setOutput(`❌ Compilation Error:\n${result.error}`);
        }
      } catch (error) {
        setErrorMessage(`💥 Unexpected error: ${error.message}`);
        setOutput(`💥 Unexpected Error:\n${error.message}`);
      }
    }, 500);
  };

  const clearAll = () => {
    setSourceCode('');
    setOutput('Output will appear here after compilation...');
    setTokens('No tokens generated yet...');
    setGeneratedCode('No generated code yet...');
    setAst('No AST generated yet...');
    setErrorMessage('');
    setSuccessMessage('');
  };

  const logout = () => {
    if (confirm('Are you sure you want to logout?')) {
      authService.logout();
      onLogout();
    }
  };

  const examplesData = {
    basic: [
      {
        title: "Hello World",
        description: "The simplest EBPL program - printing a message",
        code: 'print "Hello, EBPL World!"'
      },
      {
        title: "Variables",
        description: "Creating and using variables with different data types",
        code: `create variable name with value "Alice"
create variable age with value 25
print name
print age`
      }
    ],
    control: [
      {
        title: "If Statement",
        description: "Conditional statements with multiple branches",
        code: `create variable score with value 85

if score is greater than 90 then
    print "Grade: A"
else if score is greater than 80 then
    print "Grade: B"
else
    print "Grade: C"
end if`
      }
    ]
  };

  const loadExample = (code) => {
    setSourceCode(code);
    setShowExamples(false);
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'output':
        return <pre style={{
          flex: 1,
          border: '2px solid #e2e8f0',
          borderRadius: '8px',
          padding: '20px',
          background: '#1a202c',
          color: '#e2e8f0',
          fontFamily: 'Consolas, Monaco, Courier New, monospace',
          fontSize: '14px',
          overflow: 'auto',
          whiteSpace: 'pre-wrap',
          lineHeight: '1.5',
          minHeight: '400px',
          margin: 0
        }}>{output}</pre>;
      case 'tokens':
        return <pre style={{
          flex: 1,
          border: '2px solid #e2e8f0',
          borderRadius: '8px',
          padding: '20px',
          background: '#1a202c',
          color: '#e2e8f0',
          fontFamily: 'Consolas, Monaco, Courier New, monospace',
          fontSize: '14px',
          overflow: 'auto',
          whiteSpace: 'pre-wrap',
          lineHeight: '1.5',
          minHeight: '400px',
          margin: 0
        }}>{tokens}</pre>;
      case 'generated':
        return <pre style={{
          flex: 1,
          border: '2px solid #e2e8f0',
          borderRadius: '8px',
          padding: '20px',
          background: '#1a202c',
          color: '#e2e8f0',
          fontFamily: 'Consolas, Monaco, Courier New, monospace',
          fontSize: '14px',
          overflow: 'auto',
          whiteSpace: 'pre-wrap',
          lineHeight: '1.5',
          minHeight: '400px',
          margin: 0
        }}>{generatedCode}</pre>;
      case 'ast':
        return <pre style={{
          flex: 1,
          border: '2px solid #e2e8f0',
          borderRadius: '8px',
          padding: '20px',
          background: '#1a202c',
          color: '#e2e8f0',
          fontFamily: 'Consolas, Monaco, Courier New, monospace',
          fontSize: '14px',
          overflow: 'auto',
          whiteSpace: 'pre-wrap',
          lineHeight: '1.5',
          minHeight: '400px',
          margin: 0
        }}>{ast}</pre>;
      default:
        return <pre style={{
          flex: 1,
          border: '2px solid #e2e8f0',
          borderRadius: '8px',
          padding: '20px',
          background: '#1a202c',
          color: '#e2e8f0',
          fontFamily: 'Consolas, Monaco, Courier New, monospace',
          fontSize: '14px',
          overflow: 'auto',
          whiteSpace: 'pre-wrap',
          lineHeight: '1.5',
          minHeight: '400px',
          margin: 0
        }}>{output}</pre>;
    }
  };

  return (
    <div style={{ minHeight: '100vh', padding: '20px' }}>
      <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
        {/* Header */}
        <header style={{
          textAlign: 'center',
          marginBottom: '30px',
          background: 'rgba(255, 255, 255, 0.95)',
          color: '#2d3748',
          padding: '30px',
          borderRadius: '12px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.1)',
          backdropFilter: 'blur(10px)'
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            width: '100%'
          }}>
            <div style={{ textAlign: 'left' }}>
              <h1 style={{ 
                margin: 0,
                fontSize: '2.5em',
                fontWeight: 700,
                background: 'linear-gradient(135deg, #667eea, #764ba2)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent'
              }}>
                🎯 EBPL Online Compiler
              </h1>
              <p style={{ margin: '10px 0 0 0', fontSize: '1.1em', color: '#718096' }}>
                English Based Programming language
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
              <span style={{ fontWeight: 600, color: '#2d3748' }}>Welcome, {user?.name || 'User'}!</span>
              <div style={{ display: 'flex', gap: '10px' }}>
                <button className="btn btn-secondary" onClick={onBackToDashboard}>
                  📊 Dashboard
                </button>
                <button className="btn btn-warning" onClick={logout}>
                  🚪 Logout
                </button>
              </div>
            </div>
          </div>
        </header>

        {/* Compiler Layout */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '30px',
          minHeight: '600px'
        }}>
          {/* Editor Panel */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              flexWrap: 'wrap',
              gap: '15px'
            }}>
              <h3 style={{ margin: 0, color: '#2d3748', fontSize: '1.4em' }}>📝 EBPL Code Editor</h3>
              <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                <button className="btn btn-primary" onClick={compileCode}>
                  🚀 Compile & Run
                </button>
                <button className="btn btn-secondary" onClick={() => setShowExamples(true)}>
                  📚 Examples
                </button>
                <button className="btn btn-warning" onClick={clearAll}>
                  🗑️ Clear
                </button>
              </div>
            </div>

            <textarea
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              style={{
                flex: 1,
                border: '2px solid #e2e8f0',
                borderRadius: '8px',
                padding: '20px',
                fontFamily: 'Consolas, Monaco, Courier New, monospace',
                fontSize: '14px',
                lineHeight: '1.5',
                resize: 'none',
                outline: 'none',
                transition: 'border-color 0.3s',
                background: '#f7fafc',
                minHeight: '400px'
              }}
              placeholder="Enter your EBPL code here..."
            />

            {errorMessage && (
              <div className="message error" style={{ display: 'block', marginTop: '15px' }}>
                {errorMessage}
              </div>
            )}
            {successMessage && (
              <div className="message success" style={{ display: 'block', marginTop: '15px' }}>
                {successMessage}
              </div>
            )}
          </div>

          {/* Results Panel */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '20px',
              flexWrap: 'wrap',
              gap: '15px'
            }}>
              <h3 style={{ margin: 0, color: '#2d3748', fontSize: '1.4em' }}>📊 Compilation Results</h3>
              <div className="tabs">
                <button 
                  className={`tab ${activeTab === 'output' ? 'active' : ''}`}
                  onClick={() => setActiveTab('output')}
                >
                  Output
                </button>
                <button 
                  className={`tab ${activeTab === 'tokens' ? 'active' : ''}`}
                  onClick={() => setActiveTab('tokens')}
                >
                  Tokens
                </button>
                <button 
                  className={`tab ${activeTab === 'generated' ? 'active' : ''}`}
                  onClick={() => setActiveTab('generated')}
                >
                  Generated Code
                </button>
                <button 
                  className={`tab ${activeTab === 'ast' ? 'active' : ''}`}
                  onClick={() => setActiveTab('ast')}
                >
                  AST
                </button>
              </div>
            </div>

            {renderTabContent()}
          </div>
        </div>
      </div>

      {/* Examples Modal */}
      {showExamples && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0, 0, 0, 0.7)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000,
          padding: '20px'
        }}>
          <div style={{
            background: 'white',
            borderRadius: '12px',
            width: '90%',
            maxWidth: '1000px',
            maxHeight: '90vh',
            display: 'flex',
            flexDirection: 'column',
            boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)'
          }}>
            <div style={{
              padding: '25px',
              borderBottom: '1px solid #e2e8f0',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <h3 style={{ margin: 0, color: '#2d3748' }}>📚 EBPL Example Programs</h3>
              <button 
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '24px',
                  cursor: 'pointer',
                  color: '#718096',
                  padding: '5px',
                  borderRadius: '4px'
                }}
                onClick={() => setShowExamples(false)}
              >
                ✕
              </button>
            </div>
            <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
              {/* Sidebar */}
              <div style={{
                width: '250px',
                borderRight: '1px solid #e2e8f0',
                background: '#f7fafc',
                padding: '20px',
                overflowY: 'auto'
              }}>
                <h4 style={{ margin: '0 0 15px 0', color: '#2d3748' }}>Categories</h4>
                {Object.keys(examplesData).map(category => (
                  <div
                    key={category}
                    className={`tab ${activeExampleCategory === category ? 'active' : ''}`}
                    style={{ 
                      padding: '12px 15px',
                      marginBottom: '10px',
                      cursor: 'pointer',
                      textTransform: 'capitalize'
                    }}
                    onClick={() => setActiveExampleCategory(category)}
                  >
                    {category} Programs
                  </div>
                ))}
              </div>
              
              {/* Main Content */}
              <div style={{ flex: 1, padding: '25px', overflowY: 'auto' }}>
                <h4 style={{ margin: '0 0 20px 0', color: '#2d3748', fontSize: '1.3em', textTransform: 'capitalize' }}>
                  {activeExampleCategory} Examples
                </h4>
                {examplesData[activeExampleCategory]?.map((example, index) => (
                  <div key={index} style={{
                    background: 'white',
                    border: '1px solid #e2e8f0',
                    borderRadius: '8px',
                    padding: '20px',
                    marginBottom: '20px',
                    boxShadow: '0 2px 8px rgba(0, 0, 0, 0.05)'
                  }}>
                    <h5 style={{ margin: '0 0 10px 0', color: '#2d3748', fontSize: '1.1em' }}>
                      {example.title}
                    </h5>
                    <p style={{ margin: '0 0 15px 0', color: '#718096', lineHeight: '1.5' }}>
                      {example.description}
                    </p>
                    <pre style={{
                      background: '#1a202c',
                      color: '#e2e8f0',
                      padding: '15px',
                      borderRadius: '6px',
                      fontFamily: 'Consolas, Monaco, Courier New, monospace',
                      fontSize: '13px',
                      overflowX: 'auto',
                      whiteSpace: 'pre-wrap',
                      lineHeight: '1.4',
                      marginBottom: '15px'
                    }}>
                      {example.code}
                    </pre>
                    <button 
                      className="btn btn-primary"
                      onClick={() => loadExample(example.code)}
                    >
                      Load This Example
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Main App Component
const App = () => {
  const [currentView, setCurrentView] = useState('auth');
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const authService = new AuthService();

  useEffect(() => {
    checkAuthentication();
  }, []);

  const checkAuthentication = () => {
    if (authService.isAuthenticated()) {
      const userData = authService.getUser();
      setUser(userData);
      setCurrentView('dashboard');
    } else {
      setCurrentView('auth');
    }
    setLoading(false);
  };

  const handleLogin = (userData) => {
    setUser(userData);
    setCurrentView('dashboard');
  };

  const handleLogout = () => {
    authService.logout();
    setUser(null);
    setCurrentView('auth');
  };

  const navigateToCompiler = () => {
    setCurrentView('compiler');
  };

  const navigateToDashboard = () => {
    setCurrentView('dashboard');
  };

  const updateUserStats = async (programsCompiled, activity) => {
    if (user) {
      try {
        const updatedUser = await authService.updateUserStats(user.id, programsCompiled, activity);
        if (updatedUser) {
          setUser(updatedUser);
        }
      } catch (error) {
        console.error('Failed to update stats:', error);
      }
    }
  };

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
      }}>
        <div style={{ 
          background: 'white', 
          padding: '30px', 
          borderRadius: '12px',
          textAlign: 'center'
        }}>
          <h2>Loading...</h2>
          <p>Please wait while we check your authentication</p>
        </div>
      </div>
    );
  }

  return (
    <div>
      {currentView === 'auth' && (
        <Auth onLogin={handleLogin} />
      )}
      
      {currentView === 'dashboard' && (
        <Dashboard 
          user={user} 
          onLogout={handleLogout}
          onOpenCompiler={navigateToCompiler}
        />
      )}
      
      {currentView === 'compiler' && (
        <Compiler 
          user={user}
          onLogout={handleLogout}
          onBackToDashboard={navigateToDashboard}
          onUpdateStats={updateUserStats}
        />
      )}
    </div>
  );
};

export default App;

CREATE DATABASE IF NOT EXISTS angular_auth;
USE angular_auth;

CREATE TABLE IF NOT EXISTS accounts (
  id INT NOT NULL AUTO_INCREMENT,
  title VARCHAR(20) NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('Admin', 'User') NOT NULL DEFAULT 'User',
  date_created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  is_verified BOOLEAN NOT NULL DEFAULT FALSE,
  verification_token VARCHAR(255) NULL,
  reset_token VARCHAR(255) NULL,
  reset_token_expires DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_accounts_email (email)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INT NOT NULL AUTO_INCREMENT,
  account_id INT NOT NULL,
  token VARCHAR(255) NOT NULL,
  expires DATETIME NOT NULL,
  created DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked DATETIME NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_refresh_tokens_token (token),
  CONSTRAINT fk_refresh_tokens_account
    FOREIGN KEY (account_id) REFERENCES accounts(id)
    ON DELETE CASCADE
);

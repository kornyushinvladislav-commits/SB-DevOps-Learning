CREATE DATABASE IF NOT EXISTS fquest_12;

USE fquest_12;

CREATE TABLE ovpnclients (user_id INT AUTO_INCREMENT PRIMARY KEY, user_name VARCHAR(255), user_type INT);
        
CREATE TABLE ovpnfiles (file_id INT AUTO_INCREMENT PRIMARY KEY, file_name VARCHAR(255), file_text VARCHAR(255), user_id INT, FOREIGN KEY (user_id) REFERENCES ovpnclients (user_id) ON DELETE CASCADE);
        
CREATE TABLE IF NOT EXISTS server_files (sf_id INT NOT NULL, sfname VARCHAR(20) NOT NULL, sftext VARCHAR(20) NOT NULL);
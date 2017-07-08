package com.ikeirnez.communicationsframework.api.authentication;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by JBou on 08/07/2017.
 */
public class UsernamePasswordConnectionAuthentication implements ConnectionAuthentication {

    private HashMap<String, String> users = new HashMap<>();
    private String username;
    private String password;

    public UsernamePasswordConnectionAuthentication(String username, String password) {
        try {
            if (username == null) {
                throw new RuntimeException("Username cannot be null");
            }
            if (password == null) {
                throw new RuntimeException("Password cannot be null");
            }
            this.username = username;
            this.password = new String(MessageDigest.getInstance("SHA-256").digest(password.getBytes("UTF-8")));
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new RuntimeException("Error whilst encrypting password for authentication", e);
        }
    }

    public UsernamePasswordConnectionAuthentication(HashMap<String, String> users) {
        try {
            if (users == null) {
                throw new RuntimeException("Users cannot be null");
            }
            for (Map.Entry<String, String> entry : users.entrySet()) {
                this.users.put(entry.getKey(), new String(MessageDigest.getInstance("SHA-256").digest(entry.getValue().getBytes("UTF-8"))));
            }
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            throw new RuntimeException("Error whilst encrypting passwords for authentication", e);
        }
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public HashMap<String, String> getUsers() {
        return users;
    }

}

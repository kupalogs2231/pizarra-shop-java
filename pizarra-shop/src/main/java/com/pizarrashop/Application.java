// ============================================
// 1. Application.java (Main Entry Point)
// ============================================
package com.pizarrashop;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

// ============================================
// 2. MongoUserDAO.java (Database Operations)
// ============================================
package com.pizarrashop.dao;

import com.mongodb.client.*;
import org.bson.Document;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Repository;

@Repository
public class MongoUserDAO {
    private static final String CONNECTION_STRING = 
        "mongodb+srv://username:password@cluster0.mongodb.net/";
    private MongoClient mongoClient;
    private MongoDatabase database;
    private MongoCollection<Document> usersCollection;
    
    public MongoUserDAO() {
        try {
            mongoClient = MongoClients.create(CONNECTION_STRING);
            database = mongoClient.getDatabase("pizarrashop");
            usersCollection = database.getCollection("users");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Save user
    public boolean saveUser(String username, String password) {
        try {
            // Check if user already exists
            Document existingUser = usersCollection.find(new Document("username", username)).first();
            if (existingUser != null) {
                return false;
            }
            
            String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12));
            
            Document user = new Document()
                .append("username", username)
                .append("password", hashedPassword)
                .append("createdAt", new java.util.Date());
            
            usersCollection.insertOne(user);
            return true;
            
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    // Verify login
    public boolean verifyUser(String username, String password) {
        try {
            Document query = new Document("username", username);
            Document user = usersCollection.find(query).first();
            
            if (user != null) {
                String hashedPassword = user.getString("password");
                return BCrypt.checkpw(password, hashedPassword);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    
    public void close() {
        if (mongoClient != null) {
            mongoClient.close();
        }
    }
}

// ============================================
// 3. UserRequest.java (Request Model)
// ============================================
package com.pizarrashop.model;

public class UserRequest {
    private String username;
    private String password;
    
    public UserRequest() {}
    
    public UserRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
}

// ============================================
// 4. AuthController.java (API Endpoints)
// ============================================
package com.pizarrashop.controller;

import com.pizarrashop.dao.MongoUserDAO;
import com.pizarrashop.model.UserRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AuthController {
    
    @Autowired
    private MongoUserDAO userDAO;
    
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserRequest request) {
        Map<String, Object> response = new HashMap<>();
        
        if (request.getUsername() == null || request.getUsername().length() < 3) {
            response.put("success", false);
            response.put("message", "Username must be at least 3 characters");
            return ResponseEntity.badRequest().body(response);
        }
        
        if (request.getPassword() == null || request.getPassword().length() < 6) {
            response.put("success", false);
            response.put("message", "Password must be at least 6 characters");
            return ResponseEntity.badRequest().body(response);
        }
        
        boolean success = userDAO.saveUser(
            request.getUsername(), 
            request.getPassword()
        );
        
        if (success) {
            response.put("success", true);
            response.put("message", "Registration successful");
            return ResponseEntity.ok(response);
        } else {
            response.put("success", false);
            response.put("message", "Username already exists");
            return ResponseEntity.badRequest().body(response);
        }
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest request) {
        boolean valid = userDAO.verifyUser(
            request.getUsername(), 
            request.getPassword()
        );
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", valid);
        response.put("message", valid ? "Login successful" : "Invalid credentials");
        
        return valid ? ResponseEntity.ok(response) : 
                      ResponseEntity.status(401).body(response);
    }
}

// ============================================
// 5. WebController.java (Serve HTML Pages)
// ============================================
package com.pizarrashop.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {
    
    @GetMapping("/")
    public String index() {
        return "index.html";
    }
    
    @GetMapping("/login")
    public String login() {
        return "login.html";
    }
}
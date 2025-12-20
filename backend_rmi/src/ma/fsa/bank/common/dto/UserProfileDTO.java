package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class UserProfileDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private Integer clientId;
    private String username;
    private String role;
    private boolean active;


    private String firstName;
    private String lastName;
    private String cin;
    private String email;
    private String phone;
    private String address;
    private String clientType;

    public UserProfileDTO() {}

    public UserProfileDTO(int id, Integer clientId, String username, String role, boolean active) {
        this.id = id;
        this.clientId = clientId;
        this.username = username;
        this.role = role;
        this.active = active;
    }

    public int getId() { return id; }
    public Integer getClientId() { return clientId; }
    public String getUsername() { return username; }
    public String getRole() { return role; }
    public boolean isActive() { return active; }

    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getCin() { return cin; }
    public String getEmail() { return email; }
    public String getPhone() { return phone; }
    public String getAddress() { return address; }
    public String getClientType() { return clientType; }

    public void setId(int id) { this.id = id; }
    public void setClientId(Integer clientId) { this.clientId = clientId; }
    public void setUsername(String username) { this.username = username; }
    public void setRole(String role) { this.role = role; }
    public void setActive(boolean active) { this.active = active; }

    public void setFirstName(String firstName) { this.firstName = firstName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public void setCin(String cin) { this.cin = cin; }
    public void setEmail(String email) { this.email = email; }
    public void setPhone(String phone) { this.phone = phone; }
    public void setAddress(String address) { this.address = address; }
    public void setClientType(String clientType) { this.clientType = clientType; }
}

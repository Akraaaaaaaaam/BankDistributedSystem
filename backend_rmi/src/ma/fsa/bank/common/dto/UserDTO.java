package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class UserDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private Integer clientId;
    private String username;
    private String role;
    private boolean active;

    // NEW
    private boolean superAdmin;
    private Integer createdBy;

    public UserDTO() {}


    public UserDTO(int id, Integer clientId, String username, String role, boolean active) {
        this.id = id;
        this.clientId = clientId;
        this.username = username;
        this.role = role;
        this.active = active;
        this.superAdmin = false;
        this.createdBy = null;
    }

    public UserDTO(int id, Integer clientId, String username, String role) {
        this(id, clientId, username, role, true);
    }


    public UserDTO(int id, Integer clientId, String username, String role, boolean active, boolean superAdmin, Integer createdBy) {
        this.id = id;
        this.clientId = clientId;
        this.username = username;
        this.role = role;
        this.active = active;
        this.superAdmin = superAdmin;
        this.createdBy = createdBy;
    }

    public int getId() { return id; }
    public Integer getClientId() { return clientId; }
    public String getUsername() { return username; }
    public String getRole() { return role; }
    public boolean isActive() { return active; }

    public boolean isSuperAdmin() { return superAdmin; }
    public Integer getCreatedBy() { return createdBy; }

    public void setId(int id) { this.id = id; }
    public void setClientId(Integer clientId) { this.clientId = clientId; }
    public void setUsername(String username) { this.username = username; }
    public void setRole(String role) { this.role = role; }
    public void setActive(boolean active) { this.active = active; }

    public void setSuperAdmin(boolean superAdmin) { this.superAdmin = superAdmin; }
    public void setCreatedBy(Integer createdBy) { this.createdBy = createdBy; }
}

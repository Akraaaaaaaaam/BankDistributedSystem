package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class RegisterRequest implements Serializable {
    private static final long serialVersionUID = 1L;

    private String username;
    private String plainPassword;

    // NEW
    private int branchId;
    private String firstName;
    private String lastName;
    private String cin;
    private String email;
    private String phone;
    private String address;

    public RegisterRequest() {}

    public RegisterRequest(String username, String plainPassword) {
        this.username = username;
        this.plainPassword = plainPassword;
    }

    public RegisterRequest(String username, String plainPassword, int branchId,
                           String firstName, String lastName, String cin,
                           String email, String phone, String address) {
        this.username = username;
        this.plainPassword = plainPassword;
        this.branchId = branchId;
        this.firstName = firstName;
        this.lastName = lastName;
        this.cin = cin;
        this.email = email;
        this.phone = phone;
        this.address = address;
    }

    public String getUsername() { return username; }
    public String getPlainPassword() { return plainPassword; }

    public int getBranchId() { return branchId; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getCin() { return cin; }
    public String getEmail() { return email; }
    public String getPhone() { return phone; }
    public String getAddress() { return address; }

    public void setUsername(String username) { this.username = username; }
    public void setPlainPassword(String plainPassword) { this.plainPassword = plainPassword; }

    public void setBranchId(int branchId) { this.branchId = branchId; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public void setCin(String cin) { this.cin = cin; }
    public void setEmail(String email) { this.email = email; }
    public void setPhone(String phone) { this.phone = phone; }
    public void setAddress(String address) { this.address = address; }

    @Override
    public String toString() {
        return "RegisterRequest{username='" + username + "', branchId=" + branchId + "}";
    }
}

package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class UserProfileUpdateDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private int userId;
    private String username;

    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private String address;

    public UserProfileUpdateDTO() {}

    public UserProfileUpdateDTO(int userId, String username, String firstName, String lastName, String email, String phone, String address) {
        this.userId = userId;
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.phone = phone;
        this.address = address;
    }

    public int getUserId() { return userId; }
    public String getUsername() { return username; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getEmail() { return email; }
    public String getPhone() { return phone; }
    public String getAddress() { return address; }

    public void setUserId(int userId) { this.userId = userId; }
    public void setUsername(String username) { this.username = username; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    public void setEmail(String email) { this.email = email; }
    public void setPhone(String phone) { this.phone = phone; }
    public void setAddress(String address) { this.address = address; }
}

package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class RegisterRequest implements Serializable {
    private static final long serialVersionUID = 1L;

    private String username;
    private String plainPassword;

    public RegisterRequest() {}

    public RegisterRequest(String username, String plainPassword) {
        this.username = username;
        this.plainPassword = plainPassword;
    }

    public String getUsername() { return username; }
    public String getPlainPassword() { return plainPassword; }

    public void setUsername(String username) { this.username = username; }
    public void setPlainPassword(String plainPassword) { this.plainPassword = plainPassword; }

    @Override
    public String toString() {
        return "RegisterRequest{username='" + username + "'}";
    }
}

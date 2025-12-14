package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class RegisterResponse implements Serializable {
    private static final long serialVersionUID = 1L;

    private boolean success;
    private String message;

    public RegisterResponse() {}

    public RegisterResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }

    public void setSuccess(boolean success) { this.success = success; }
    public void setMessage(String message) { this.message = message; }

    @Override
    public String toString() {
        return "RegisterResponse{success=" + success + ", message='" + message + "'}";
    }
}

package ma.fsa.bank.common.dto;

import java.io.Serializable;

public class BranchDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private int id;
    private String code;
    private String name;
    private String city;

    public BranchDTO() {}

    public BranchDTO(int id, String code, String name, String city) {
        this.id = id;
        this.code = code;
        this.name = name;
        this.city = city;
    }

    public int getId() { return id; }
    public String getCode() { return code; }
    public String getName() { return name; }
    public String getCity() { return city; }

    public void setId(int id) { this.id = id; }
    public void setCode(String code) { this.code = code; }
    public void setName(String name) { this.name = name; }
    public void setCity(String city) { this.city = city; }

    @Override
    public String toString() {
        return "BranchDTO{id=" + id + ", code='" + code + "', name='" + name + "', city='" + city + "'}";
    }
}

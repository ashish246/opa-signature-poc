
import com.fasterxml.jackson.annotation.JsonProperty;

public class FilesPOJO {

    @JsonProperty("name")
    private String name;

    @JsonProperty("sha-256")
    private String sha256;


    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}

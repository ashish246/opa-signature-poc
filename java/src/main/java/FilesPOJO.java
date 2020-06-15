import com.fasterxml.jackson.annotation.JsonProperty;

public class FilesPOJO {

    @JsonProperty("name")
    private String name;

    @JsonProperty("hash")
    private String hash;

    @JsonProperty("algorithm")
    private String algorithm;


    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class SignaturePOJO {

    @JsonProperty("signature")
    private String signature;

    @JsonProperty("files")
    private List<FilesPOJO> files;

    public String getSignature() {
        return signature;
    }

    public List<FilesPOJO> getFiles() {
        return files;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public void setFiles(List<FilesPOJO> files) {
        this.files = files;
    }
}

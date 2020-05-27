import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class SignaturePOJO {

    @JsonProperty("signature")
    private String signature;

    @JsonProperty("files")
    @JsonInclude(JsonInclude.Include.NON_NULL)
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

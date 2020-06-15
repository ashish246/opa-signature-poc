import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignaturePOJO {

    @JsonProperty("signatures")
    private List<String> signatures;

    public List<String> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<String> signatures) {
        this.signatures = signatures;
    }
}

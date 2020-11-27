package src;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@ToString
@NoArgsConstructor
class PPKeys {
    private String privateKey;
    private String publicKey;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivatekey() {
        return privateKey;
    }

    public void setPrivatekey(String privatekey) {
        this.privateKey = privatekey;
    }
}
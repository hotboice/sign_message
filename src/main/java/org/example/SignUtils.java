package org.example;

import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class SignUtils {

    private static final String address = "";
    private static final String key = "-";

    public static void main(String[] args) throws Exception {
        String message = "message";
        String signature = sign(message, new BigInteger(key, 16));
        System.out.printf("message: -> %s%n", message);
        System.out.printf("address: -> %s%n", address);
        System.out.printf("key: -> %s%n", key);
        System.out.printf("signature: -> %s%n", signature);

        verify_sign(signature, message);
    }

    /**
     * @param message 消息明文
     * @param privateKey 签名者私钥
     * @return signature 签名结果
     */
    private static String sign(String message, BigInteger privateKey) {
        BigInteger pubKey = Sign.publicKeyFromPrivate(privateKey);
        ECKeyPair keyPair = new ECKeyPair(privateKey, pubKey);
        Sign.SignatureData signature = Sign.signPrefixedMessage(message.getBytes(StandardCharsets.UTF_8), keyPair);
        byte[] retrieval = new byte[65];
        System.arraycopy(signature.getR(), 0, retrieval, 0, 32);
        System.arraycopy(signature.getS(), 0, retrieval, 32, 32);
        System.arraycopy(signature.getV(), 0, retrieval, 64, 1);
        return Numeric.toHexString(retrieval);
    }

    /**
     * @param signature 签名结果
     * @param message 消息明文
     * @throws Exception
     */
    private static void verify_sign(String signature, String message) throws Exception {
        String r = signature.substring(0, 66);
        String s = "0x" + signature.substring(66, 130);
        String v = "0x" + signature.substring(130, 132);

        String sign_address = "0x" + Keys.getAddress(
            Sign.signedPrefixedMessageToKey(message.getBytes(StandardCharsets.UTF_8),
                new Sign.SignatureData(Numeric.hexStringToByteArray(v)[0],
                    Numeric.hexStringToByteArray(r), Numeric.hexStringToByteArray(s)))
            .toString(16));

        System.out.printf("verify_sign address: -> %s%n", sign_address);
        System.out.println(address.equalsIgnoreCase(sign_address));
    }
}
package org.example;

import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.DynamicBytes;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Bytes4;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class CheckSignUtil {
    private static final String RECOVER_HEX = "0x1626ba7e";
    private static final String UNIPASS_PREFIXED = "\u0018UniPass Signed Message:\n";
    private static final String SIGN_RPC_ENDPOINT = "https://rpc.ankr.com/polygon_mumbai";
    private static final String SIGN_CHECK_CONTRACT = "0x6939dBfaAe305FCdA6815ebc9a297997969d39aB";

    public static void main(String[] args) throws Exception {
        String address = "0x1";

        String message_eip191 = "Welcome to Sugar!\n     Click to sign in and accept the Terms of Use: http://web-front.isugar.io/home\n     This request will not trigger a blockchain transaction or cost any gas fees.\n     Wallet address: 0x1\n     Nonce: rutQidLEJMgwYxfv1AgsvN\n";
        String signature_eip191 = "0xe9406024c316fd80b3bda592473faed4e99197fc227480be2ace0e0d1753f57724e8fa88e8bb767ce188d8e8e5948ba233da117f4858a2deca14a6d3b5ad5f141b";
        System.out.printf("eip191: %s", validSignature(message_eip191, signature_eip191, address));

        String message_unipass = "Welcome to UniPass!";
        String signature_unipass = "0x000001d0bdf2f92cfc6de71d00ca5413c19500ae912b215ca680bff55d2c4e971401fd2852989416ea19622985bfb57e341aa7875b17aae708dc0c03375250181ac1da1c020000003c000000640000000002007e7649ccd0315628dabe5256cd050d4ce7e1824d1217dba20cc5e3e5626553970000003c000000000000003c0000c06495b106de8a0701ff5e84d9f8a5c9d711b1b6000000280000000000000000";
        System.out.printf("unipass: %s", validSignature(message_unipass, signature_unipass, address));
    }

    /**
     * @param message
     * @param signature
     * @param address
     * @return true or false
     */
    public static boolean validSignature(@NotNull String message, @NotNull String signature, @NotNull String address) throws Exception {
        return signature.length() == 324 ? unipass(message, signature, address) : eip191(message, signature, address);
    }

    private static boolean unipass(String messageStr, String signature, String address) throws IOException {
        Web3j web3j = Web3j.build(new HttpService(SIGN_RPC_ENDPOINT));
        byte[] sig = Hex.decode(signature.startsWith("0x") ? signature.substring(2) : signature);
        byte[] message = messageStr.getBytes(StandardCharsets.UTF_8);
        byte[] prefix = UNIPASS_PREFIXED.concat(String.valueOf(message.length)).getBytes();
        byte[] result = new byte[prefix.length + message.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(message, 0, result, prefix.length, message.length);
        message = Hash.sha3(result);

        Function function = new Function("isValidSignature",
            Arrays.asList(new Bytes32(message), new DynamicBytes(sig)),
            List.of(new TypeReference<Bytes4>() {}));
        EthCall ethCall = web3j.ethCall(
            Transaction.createEthCallTransaction(address, SIGN_CHECK_CONTRACT, FunctionEncoder.encode(function)),
            DefaultBlockParameterName.LATEST).send();
        List<Type> someTypes = FunctionReturnDecoder.decode(ethCall.getValue(), function.getOutputParameters());
        if(someTypes.size() == 1) {
            Bytes4 bytes4 = (Bytes4) someTypes.get(0);
            return Numeric.toHexString(bytes4.getValue()).equalsIgnoreCase(RECOVER_HEX);
        }
        return false;
    }

    private static boolean eip191(String message, String signature, String address) throws Exception {
        String r = signature.substring(0, 66);
        String s = "0x" + signature.substring(66, 130);
        String v = "0x" + signature.substring(130, 132);

        String signAddress = "0x" + Keys.getAddress(
            Sign.signedPrefixedMessageToKey(message.getBytes(StandardCharsets.UTF_8),
            new Sign.SignatureData(Numeric.hexStringToByteArray(v)[0],
            Numeric.hexStringToByteArray(r),
            Numeric.hexStringToByteArray(s))).toString(16));
        return address.equalsIgnoreCase(signAddress);
    }
}
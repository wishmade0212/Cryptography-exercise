import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ManualCMAC {

    private static final int BLOCK_SIZE = 16;
    private static final byte[] RB = new byte[16];

    static {
        RB[15] = (byte) 0x87; // Polynomial constant for 128-bit block
    }

    public static void main(String[] args) throws Exception {
        String keyStr = "onetwothfourfive";
        String msgStr = "Hello CMAC!";
        
        ManualCMAC cmac = new ManualCMAC();
        List<String> steps = cmac.calculate(keyStr, msgStr);
        
        steps.forEach(System.out::println);
    }

    private byte[] xorBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private byte[] leftShift(byte[] b) {
        byte[] res = new byte[16];
        int overflow = 0;
        for (int i = 15; i >= 0; i--) {
            int current = b[i] & 0xFF;
            res[i] = (byte) ((current << 1) | overflow);
            overflow = (current & 0x80) != 0 ? 1 : 0;
        }
        return res;
    }

    public List<String> calculate(String keyStr, String msgStr) throws Exception {
        List<String> steps = new ArrayList<>();
        steps.add("Original Key: " + keyStr);
        steps.add("Message: " + msgStr);

        byte[] key = keyStr.getBytes();
        byte[] msg = msgStr.getBytes();

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Generate Subkeys
        byte[] L = cipher.doFinal(new byte[BLOCK_SIZE]);
        
        byte[] K1 = leftShift(L);
        if ((L[0] & 0x80) != 0) K1 = xorBytes(K1, RB);

        byte[] K2 = leftShift(K1);
        if ((K1[0] & 0x80) != 0) K2 = xorBytes(K2, RB);

        steps.add("[3] L: " + bytesToHex(L));
        steps.add("[4] K1: " + bytesToHex(K1));
        steps.add("[5] K2: " + bytesToHex(K2));

        // Block Splitting
        int n = msg.length;
        int nBlocks = (n == 0) ? 1 : (n + BLOCK_SIZE - 1) / BLOCK_SIZE;
        boolean isComplete = (n != 0 && n % BLOCK_SIZE == 0);

        byte[] MLast;
        int lastBlockStart = (nBlocks - 1) * BLOCK_SIZE;
        byte[] lastBlock = Arrays.copyOfRange(msg, lastBlockStart, n);

        if (isComplete) {
            MLast = xorBytes(lastBlock, K1);
            steps.add("[6] Complete block -> M_last = last XOR K1");
        } else {
            byte[] paddedLast = new byte[BLOCK_SIZE];
            System.arraycopy(lastBlock, 0, paddedLast, 0, lastBlock.length);
            paddedLast[lastBlock.length] = (byte) 0x80;
            MLast = xorBytes(paddedLast, K2);
            steps.add("[6] Incomplete block -> Padded last XOR K2");
        }

        // Process Chunks
        byte[] X = new byte[BLOCK_SIZE];
        for (int i = 0; i < nBlocks - 1; i++) {
            byte[] block = Arrays.copyOfRange(msg, i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
            byte[] Y = xorBytes(X, block);
            X = cipher.doFinal(Y);
            steps.add(String.format("[8.%d] X: %s", i + 1, bytesToHex(X)));
        }

        byte[] Y = xorBytes(X, MLast);
        byte[] T = cipher.doFinal(Y);

        steps.add("[9] Final Y: " + bytesToHex(Y));
        steps.add("[10] CMAC Tag: " + bytesToHex(T));

        return steps;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}


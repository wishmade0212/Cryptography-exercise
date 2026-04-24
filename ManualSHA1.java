import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class ManualSHA1 {

    public static void main(String[] args) throws Exception {
        String input = "abc"; // Example input
        ManualSHA1 sha1 = new ManualSHA1();
        List<String> steps = sha1.calculate(input);
        
        for (String step : steps) {
            System.out.println(step);
        }
    }

    private int leftRotate(int n, int b) {
        return (n << b) | (n >>> (32 - b));
    }

    public List<String> calculate(String message) throws Exception {
        List<String> steps = new ArrayList<>();

        // Pre-processing
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        int originalLenBytes = messageBytes.length;
        long origLenInBits = (long) originalLenBytes * 8;

        steps.add("Input message: " + message);
        steps.add("Input bytes length: " + originalLenBytes);
        steps.add("Input bits length: " + origLenInBits);
        steps.add("");

        // Padding
        int padLength = (originalLenBytes % 64 < 56) ? (64 - originalLenBytes % 64) : (128 - originalLenBytes % 64);
        byte[] padded = new byte[originalLenBytes + padLength];
        System.arraycopy(messageBytes, 0, padded, 0, originalLenBytes);
        
        padded[originalLenBytes] = (byte) 0x80;
        steps.add("After appending 0x80:");
        steps.add(bytesToHex(new byte[]{padded[originalLenBytes]}));

        // Append length (64-bit big-endian)
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 1 - i] = (byte) ((origLenInBits >>> (8 * i)) & 0xFF);
        }

        steps.add("After zero padding and appending original length:");
        steps.add(bytesToHex(padded));
        steps.add("Final padded length in bytes: " + padded.length);
        steps.add("Total chunks: " + (padded.length / 64));
        steps.add("");

        // Initial Variables
        int h0 = 0x67452301;
        int h1 = 0xEFCDAB89;
        int h2 = 0x98BADCFE;
        int h3 = 0x10325476;
        int h4 = 0xC3D2E1F0;

        steps.add(String.format("Initial hash values:\nh0=%08x, h1=%08x, h2=%08x, h3=%08x, h4=%08x\n", h0, h1, h2, h3, h4));

        // Process Chunks
        for (int chunkIdx = 0; chunkIdx < padded.length / 64; chunkIdx++) {
            int offset = chunkIdx * 64;
            steps.add("=== Chunk " + (chunkIdx + 1) + " ===");

            int[] w = new int[80];
            for (int i = 0; i < 16; i++) {
                int bOmit = offset + (i * 4);
                w[i] = ((padded[bOmit] & 0xFF) << 24) | ((padded[bOmit + 1] & 0xFF) << 16) 

                     | ((padded[bOmit + 2] & 0xFF) << 8) | (padded[bOmit + 3] & 0xFF);
            }

            for (int i = 16; i < 80; i++) {
                w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            int a = h0, b = h1, c = h2, d = h3, e = h4;

            for (int i = 0; i < 80; i++) {
                int f, k;
                if (i <= 19) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (i <= 39) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i <= 59) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                int temp = leftRotate(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = leftRotate(b, 30);
                b = a;
                a = temp;

                if (i == 0 || i == 19 || i == 39 || i == 59 || i == 79) {
                    steps.add(String.format("Round %02d: a=%08x b=%08x c=%08x d=%08x e=%08x", i, a, b, c, d, e));
                }
            }

            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
            steps.add(String.format("Updated hash: h0=%08x, h1=%08x, h2=%08x, h3=%08x, h4=%08x\n", h0, h1, h2, h3, h4));
        }

        String result = String.format("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4);
        
        // Verification
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] verifyBytes = md.digest(message.getBytes(StandardCharsets.UTF_8));
        String verify = bytesToHex(verifyBytes);

        steps.add("Final SHA-1 Hash: " + result);
        steps.add("Verified (MessageDigest): " + verify);
        steps.add("Match: " + (result.equals(verify) ? "YES" : "NO"));

        return steps;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}


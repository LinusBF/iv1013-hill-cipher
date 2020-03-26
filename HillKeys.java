import org.jscience.mathematics.number.LargeInteger;
import org.jscience.mathematics.number.ModuloInteger;
import org.jscience.mathematics.vector.DenseMatrix;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.ThreadLocalRandom;

public class HillKeys {
    private static int radix = -1;
    private static int blockSize = -1;
    private static String keyPath = "";
    public static void main(String[] args) throws IOException {
        if(args.length != 3){
            throw new IllegalArgumentException("Expected: HillCipher <radix> <blocksize> <keyfile>");
        } else {
            parseArgs(args);
        }
        verifyArguments();

        ModuloInteger.setModulus(LargeInteger.valueOf(radix));
        DenseMatrix<ModuloInteger> generatedKey = null;
        while(generatedKey == null || !isInvertible(generatedKey)){
            generatedKey = generateRandomMatrix();
        }
        writeKeyToFile(generatedKey);
    }

    private static boolean isInvertible(DenseMatrix<ModuloInteger> matrix) {
        try {
            matrix.inverse();
            return true;
        } catch (ArithmeticException e) {
            return false;
        }
    }

    private static DenseMatrix<ModuloInteger> generateRandomMatrix(){
        ModuloInteger[][] values = new ModuloInteger[blockSize][blockSize];

        for(int i = 0; i < blockSize; i++) {
            for (int j = 0; j < blockSize; j++) {
                values[i][j] = ModuloInteger.valueOf(LargeInteger.valueOf(ThreadLocalRandom.current().nextInt(0, radix)));
            }
        }

        return DenseMatrix.valueOf(values);
    }

    private static void writeKeyToFile(DenseMatrix<ModuloInteger> key) throws IOException {
        File output = new File(keyPath);
        FileWriter encryptedWriter = new FileWriter(output);
        for(int i = 0; i < key.getNumberOfColumns(); i++){
            for(int j = 0; j < key.getNumberOfRows(); j++) {
                if(j != 0){
                    encryptedWriter.write(" ");
                }
                encryptedWriter.write(key.get(i, j).toString());
            }
            if(i != key.getNumberOfColumns() - 1) {
                encryptedWriter.write("\n");
            }
        }
        encryptedWriter.close();
    }

    private static void parseArgs(String[] args) {
        radix = Integer.parseInt(args[0]);
        blockSize = Integer.parseInt(args[1]);
        keyPath = args[2];
    }

    private static void verifyArguments() throws IllegalArgumentException {
        if(
                !(radix > 0 && radix <= 256)
                || !(blockSize > 0 && blockSize <= 8)
        ) {
            throw new IllegalArgumentException("Unexpected arguments! Radix must be between 1 and 256, block size must be between 1 and 8!");
        }
    }
}

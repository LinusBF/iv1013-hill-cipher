import org.jscience.mathematics.number.LargeInteger;
import org.jscience.mathematics.number.ModuloInteger;
import org.jscience.mathematics.vector.DenseMatrix;
import org.jscience.mathematics.vector.DenseVector;
import org.jscience.mathematics.vector.DimensionException;
import org.w3c.dom.ranges.RangeException;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

public class HillDecipher {
    private static int radix = -1;
    private static int blockSize = -1;
    private static String keyPath = "";
    private static String encryptedTextPath = "";
    private static String decryptedOutputPath = "";

    private static ModuloInteger stringToModInt(String s) {
        return ModuloInteger.valueOf(s.subSequence(0, s.length()));
    }

    private static ModuloInteger intToModInt(int i) {
        return ModuloInteger.valueOf(LargeInteger.valueOf(i));
    }

    private static boolean isInvertible(DenseMatrix<ModuloInteger> matrix) {
        try {
            matrix.inverse();
            return true;
        } catch (ArithmeticException | DimensionException e) {
            return false;
        }
    }

    public static void main(String[] args) throws IOException {
        try {
            if (args.length != 5) {
                throw new IllegalArgumentException("Expected: HillCipher <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
            } else {
                parseArgs(args);
            }
            verifyArguments();

            ModuloInteger.setModulus(LargeInteger.valueOf(radix));
            DenseMatrix<ModuloInteger> keyMatrix = getKey().inverse();
            InputStream input = HillDecipher.class.getResourceAsStream(encryptedTextPath);
            File output = new File(decryptedOutputPath);
            Scanner encryptedReader = new Scanner(input);
            encryptedReader.useDelimiter("\\s+");
            FileWriter decryptWriter = new FileWriter(output);
            applyKeyToStream(encryptedReader, decryptWriter, keyMatrix);
        } catch (IllegalArgumentException | RangeException | VerifyError e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    }

    private static void applyKeyToStream(Scanner input, FileWriter output, DenseMatrix<ModuloInteger> key) throws IOException, RangeException {
        while (input.hasNext()) {
            ModuloInteger[] chars = new ModuloInteger[blockSize];
            boolean cutoff = false;
            for(int i = 0; i < blockSize; i++){
                if(input.hasNext()){
                    chars[i] = stringToModInt(input.next());
                } else {
                    cutoff = true;
                    break;
                }
                if(chars[i].isGreaterThan(intToModInt(radix - 1))
                        || chars[i].isLessThan(intToModInt(0))
                ){
                    throw new RangeException(RangeException.BAD_BOUNDARYPOINTS_ERR, "Some input values are larger than the radix!");
                }
            }
            if(cutoff){
                break;
            }
            DenseVector<ModuloInteger> valueToEncrypt = DenseVector.valueOf(chars);
            DenseVector<ModuloInteger> encrypted = key.times(valueToEncrypt);
            for(int i = 0; i < encrypted.getDimension(); i++) {
                if(!encrypted.get(i).equals(ModuloInteger.valueOf(LargeInteger.valueOf(0)))){
                    if(i != 0){
                        output.write(" ");
                    }
                    output.write(encrypted.get(i).toString());
                }
            }
            output.write(" ");
        }
        output.close();
    }

    private static void parseArgs(String[] args) {
        radix = Integer.parseInt(args[0]);
        blockSize = Integer.parseInt(args[1]);
        keyPath = args[2];
        decryptedOutputPath = args[3];
        encryptedTextPath = args[4];
    }

    private static void verifyArguments() throws IllegalArgumentException {
        if(
            !(radix > 0 && radix <= 256)
            || !(blockSize > 0 && blockSize <= 8)
            || !(new File(keyPath).isFile() && new File(keyPath).canRead())
            || !(new File(encryptedTextPath).isFile() && new File(encryptedTextPath).canRead())
        ) {
            throw new IllegalArgumentException("Unexpected arguments! Radix must be between 1 and 256, block size must be between 1 and 8, key file and cipher-text file must be existing and readable files!");
        }
    }

    private static DenseMatrix<ModuloInteger> getKey() throws VerifyError {
        InputStream input = HillDecipher.class.getResourceAsStream(keyPath);
        Scanner reader = new Scanner(input);
        ModuloInteger[][] keyValues = new ModuloInteger[blockSize][blockSize];
        VerifyError incorrectSizeError = new VerifyError("Invalid key matrix supplied! Incorrect shape!");
        int i = 0;
        while(reader.hasNextLine()){
            int j = 0;
            String row = reader.nextLine();
            for(String value : row.split("\\s+")){
                keyValues[i][j] = stringToModInt(value);
                j++;
            }
            if(j != blockSize){
                throw incorrectSizeError;
            }
            i++;
        }
        if(i != blockSize){
            throw incorrectSizeError;
        }
        DenseMatrix<ModuloInteger> key = DenseMatrix.valueOf(keyValues);
        if(!isInvertible(key)){
            throw new VerifyError("Invalid key matrix supplied! Not invertible!");
        }
        return key;
    }
}

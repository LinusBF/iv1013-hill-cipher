import org.jscience.mathematics.number.*;
import org.jscience.mathematics.vector.*;
import org.w3c.dom.ranges.RangeException;

import java.io.*;
import java.util.Scanner;

public class HillCipher {
    private static int radix = -1;
    private static int blockSize = -1;
    private static String keyPath = "";
    private static String plainInputPath = "";
    private static String encryptedOutputPath = "";

    private static ModuloInteger stringToModInt(String s) {
        return ModuloInteger.valueOf(s.subSequence(0, s.length()));
    }

    private static ModuloInteger intToModInt(int i) {
        return ModuloInteger.valueOf(LargeInteger.valueOf(i));
    }

    public static void main(String[] args) throws IllegalArgumentException, IOException {
        try {
            if (args.length != 5) {
                throw new IllegalArgumentException("Expected: HillCipher <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
            } else {
                parseArgs(args);
            }
            verifyArguments();

            ModuloInteger.setModulus(LargeInteger.valueOf(radix));
            DenseMatrix<ModuloInteger> keyMatrix = getKey();
            InputStream input = HillCipher.class.getResourceAsStream(plainInputPath);
            File output = new File(encryptedOutputPath);
            Scanner plainReader = new Scanner(input);
            plainReader.useDelimiter("\\s+");
            FileWriter encryptedWriter = new FileWriter(output);
            applyKeyToStream(plainReader, encryptedWriter, keyMatrix);
        } catch (IllegalArgumentException | RangeException | VerifyError e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    }

    private static void applyKeyToStream(Scanner input, FileWriter output, DenseMatrix<ModuloInteger> key) throws IOException {
        while (input.hasNext()) {
            ModuloInteger[] chars = new ModuloInteger[blockSize];
            for(int i = 0; i < blockSize; i++){
                if(input.hasNext()){
                    chars[i] = stringToModInt(input.next());
                } else {
                    chars[i] = stringToModInt("0");
                }
                if(chars[i].isGreaterThan(intToModInt(radix - 1))
                || chars[i].isLessThan(intToModInt(0))
                ){
                    throw new RangeException(RangeException.BAD_BOUNDARYPOINTS_ERR, "Some input values are larger than the radix!");
                }
            }

            DenseVector<ModuloInteger> valueToEncrypt = DenseVector.valueOf(chars);
            DenseVector<ModuloInteger> encrypted = key.times(valueToEncrypt);
            for(int i = 0; i < encrypted.getDimension(); i++) {
                if(i != 0){
                    output.write(" ");
                }
                output.write(encrypted.get(i).toString());
            }
            output.write(" ");
        }
        output.close();
    }

    private static void parseArgs(String[] args) {
        radix = Integer.parseInt(args[0]);
        blockSize = Integer.parseInt(args[1]);
        keyPath = args[2];
        plainInputPath = args[3];
        encryptedOutputPath = args[4];
    }

    private static void verifyArguments() throws IllegalArgumentException {
        if(
            !(radix > 0 && radix <= 256)
            || !(blockSize > 0 && blockSize <= 8)
            || !(new File(keyPath).isFile() && new File(keyPath).canRead())
            || !(new File(plainInputPath).isFile() && new File(plainInputPath).canRead())
        ) {
            throw new IllegalArgumentException("Unexpected arguments! Radix must be between 1 and 256, block size must be between 1 and 8, key file and plain text must be existing and readable files!");
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
        return DenseMatrix.valueOf(keyValues);
    }
}

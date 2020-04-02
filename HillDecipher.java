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
import java.util.ArrayList;
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
                throw new IllegalArgumentException("Expected: HillDecipher <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
            } else {
                parseArgs(args);
            }
            verifyArguments();

            ModuloInteger.setModulus(LargeInteger.valueOf(radix));
            DenseMatrix<ModuloInteger> keyMatrix = getKey().inverse();
            InputStream sizeInput = HillDecipher.class.getResourceAsStream(encryptedTextPath);
            InputStream input = HillDecipher.class.getResourceAsStream(encryptedTextPath);
            File output = new File(decryptedOutputPath);
            Scanner encryptedSizeReader = new Scanner(sizeInput);
            encryptedSizeReader.useDelimiter("\\s+");
            int fileSize = getFileSize(encryptedSizeReader);
            encryptedSizeReader.close();
            FileWriter decryptWriter = new FileWriter(output);
            Scanner encryptedReader = new Scanner(input);
            encryptedReader.useDelimiter("\\s+");
            applyKeyToStream(encryptedReader, decryptWriter, keyMatrix, fileSize);
        } catch (IllegalArgumentException | RangeException | VerifyError e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    }

    private static void applyKeyToStream(Scanner input, FileWriter output, DenseMatrix<ModuloInteger> key, int size) throws IOException, RangeException {
        int count = 0;
        ArrayList<DenseVector<ModuloInteger>> lastTwoBlocks = new ArrayList<>();
        while (input.hasNext()) {
            ArrayList<ModuloInteger> chars = new ArrayList<>();
            for(int i = 0; i < blockSize; i++){
                count = count + 1;
                if(input.hasNext()){
                    chars.add(i, stringToModInt(input.next()));
                    if(chars.get(i).isGreaterThan(intToModInt(radix - 1))
                            || chars.get(i).isLessThan(intToModInt(0))
                    ){
                        throw new RangeException(RangeException.BAD_BOUNDARYPOINTS_ERR, "Some input values are larger than the radix!");
                    }
                }
            }
            DenseVector<ModuloInteger> decrypted = decryptChars(key, chars);
            if(count > size - 2*blockSize){
                lastTwoBlocks.add(decrypted);
            } else {
                writeDecryptedChars(output, decrypted);
            }
        }
        removePadding(output, lastTwoBlocks);
        output.write("\n");
        input.close();
        output.close();
    }

    private static DenseVector<ModuloInteger> decryptChars(DenseMatrix<ModuloInteger> key, ArrayList<ModuloInteger> chars) {
        DenseVector<ModuloInteger> valueToDecrypt = DenseVector.valueOf(chars);
        return key.times(valueToDecrypt);
    }

    private static void writeDecryptedChars(FileWriter output, DenseVector<ModuloInteger> decrypted) throws IOException {
        for(int i = 0; i < decrypted.getDimension(); i++) {
            if(i != 0){
                output.write(" ");
            }
            output.write(decrypted.get(i).toString());
        }
        output.write(" ");
    }

    private static void removePadding(FileWriter output, ArrayList<DenseVector<ModuloInteger>> lastTwoBlocks) throws IOException {
        int sizeOfPadding = lastTwoBlocks.get(1).get(blockSize - 1).intValue();
        for(int i = 0; i < blockSize - sizeOfPadding; i++){
            output.write(lastTwoBlocks.get(0).get(i).toString());
            if (i != blockSize - sizeOfPadding - 1) {
                output.write(" ");
            }
        }
    }

    private static int getFileSize(Scanner input) {
        int size = 0;
        while(input.hasNext()){
            input.next();
            size++;
        }
        return size;
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

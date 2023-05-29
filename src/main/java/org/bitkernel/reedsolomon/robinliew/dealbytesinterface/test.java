package org.bitkernel.reedsolomon.robinliew.dealbytesinterface;

import java.util.Arrays;

/**
 * @author RobinLiew 2017.9.21
 */
public class test {
    public static void main(String[] args) {

        IRSErasureCorrection rsProcessor = new RSErasureCorrectionImpl();

        byte[] data = new byte[1000];
        for (int i = 0; i < data.length; i++) {
            data[i] = 1;
        }
        for (int i = 0; i < 500; i++) {
            data[i] = (byte) (16 + i);
        }


        int sliceCount = 4;//The data is 4 copies(数据为4份)
        int fecSliceCount = 2;//2 copies of erasure redundancy(纠删冗余为2份)
        int sliceLength = data.length / sliceCount;
        byte[] en_data;
        en_data = rsProcessor.encoder(data, sliceLength, sliceCount, fecSliceCount);

//==================Test use: second pieces of data are lost, and the decoding code has the corresponding test code(测试使用：让第二片数据丢失，解码代码中也有对应的测试代码)===================
        byte[] temp = new byte[250];
        System.arraycopy(temp, 0, en_data, 250, 250);
//============================================================================================================================================================================

        boolean[] eraserFlag = new boolean[sliceCount + fecSliceCount];
        Arrays.fill(eraserFlag, true);
        eraserFlag[1] = false;

        int result = rsProcessor.decoder(en_data, sliceLength, sliceCount, fecSliceCount = 2, eraserFlag);
        for (int i = 0; i < 1000; i++) {
            if(data[i] != en_data[i]) {
                System.out.println("失败");
            }
        }
        System.out.println("complete test!");//测试完毕！
    }

}

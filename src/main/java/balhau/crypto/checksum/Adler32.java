/**
 * A package balhau.crypto.checksum consiste num conjunto de algoritmos do tipo Checksum.
 */
package balhau.crypto.checksum;

import balhau.utils.Mask;

/**
 * Classe que implementa o algoritmo de checksum Adler-32.
 * RFC-1950
 * @author balhau
 *
 */
public class Adler32 {
	/**
	 * Maior primo inferior a 2^16
	 */
	public static int BASE=65521;
	private long adler;
	/**
	 * Construtor da classe
	 */
	public Adler32(){
		reset();
	}
	/**
	 * Método que reinicia o valor à variável interna da classe que representa
	 * o checksum. Esta função deve ser utilizada sempre que se pretende iniciar
	 * o cômputo de um novo checksum. 
	 */
	public void reset(){
		adler=1L;
	}
	
	/**
	 * Método privado que efectua o cômputo do adler checksum para um conjunto de
	 * bytes  
	 * @param buff {@link byte[]} representa o buffer
	 * @return {@link long} checksum
	 */
	private long update_adler32(byte[] buff){
		long s1=adler&Mask.MASK16;
		long s2=(adler>>16)&Mask.MASK16;
		for(int i=0;i<buff.length;i++){
			s1=(s1+buff[i])%BASE;
			s2=(s2+s1)%BASE;
		}
		return (s2<<16)+s1;
	}
	/**
	 * Interface pública para o método de cálculo do checksum.
	 * Este método deve ser invocado quando se pretende calcular o checksum
	 * de um grande volume de dados.
	 * @param buff {@link byte[]} buffer de bytes
	 */
	public void update(byte[] buff){
		adler=update_adler32(buff);
	}
	
	/**
	 * Método que devolve directamente o checksum para um conjunto de {@link byte}'s.
	 * @param bts {@link byte[]} dados para cômputo do checksum
	 * @return {@link long} checksum
	 */
	public long getAdler32(byte[] bts){
		reset();
		adler=update_adler32(bts);
		return adler;
	}
	
	/**
	 * Método que devolve o valor actual de checksum 
	 * @return {@link long} checksum actual
	 */
	public long getAdler32(){
		return adler;
	}
}

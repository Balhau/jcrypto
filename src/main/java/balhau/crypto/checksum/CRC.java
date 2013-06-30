package balhau.crypto.checksum;

import balhau.utils.Mask;

/**
 * Classe para implementação de mecanismos Cyclic Redundancy Check (CRC) 
 * @author balhau
 *
 */
public class CRC {
	/**
	 * Constantes que mascaram o último bit para os vários modos de CRC
	 */
	public static final long LASTBITMASK1=0x1L;
	public static final long LASTBITMASK4=0x8L;
	public static final long LASTBITMASK5=0x10L;
	public static final long LASTBITMASK6=0x20L;
	public static final long LASTBITMASK7=0x40L;
	public static final long LASTBITMASK8=0x80L;
	public static final long LASTBITMASK10=0x200L;
	public static final long LASTBITMASK11=0x400L;
	public static final long LASTBITMASK12=0x800L;
	public static final long LASTBITMASK15=0x4000L;
	public static final long LASTBITMASK16=0x8000L;
	public static final long LASTBITMASK24=0x800000L;
	public static final long LASTBITMASK32=0x80000000L;
	public static final int LOOKUP_TABLE_LENGTH=0x100;
	
	/**
	 * Método estático que permite a criação de uma tabela de CRC para um determinado tipo de Check
	 * @param tipo
	 * @return
	 */
	public static long[] geraCRCTable(CRCType tipo){
		long bitmask=tipo.getBitMask();
		long polinomio=tipo.getPolinomio();
		int BITLEN=8;
		long crc_val;
		long array[]=new long[LOOKUP_TABLE_LENGTH];
		for(int i=0;i<LOOKUP_TABLE_LENGTH;i++){
			crc_val=i;
			for(int j=0;j<BITLEN;j++){
				if((crc_val&1)>0)
					crc_val=((polinomio&bitmask)^(crc_val>>>1))&bitmask;
				else
					crc_val=crc_val>>>1;
			}
			crc_val=crc_val&bitmask;
			array[i]=crc_val;
		}
		return array;
	}
	
	public long getCRC(){
		return this.crc_sum;
	}
	/**
	 * Método que inicializa as variáveis necessárias para o computo do crc.
	 * Este método deve ser invocado aquando a computação de crc por blocos
	 * @see endCRC
	 * @see update
	 */
	public void initCRC(){
		this.crc_sum=this.tipo.getBitMask();
		this.lookup_table=geraCRCTable();
	}
	/**
	 * Método que finaliza o computo do CRC.
	 * @see initCRC
	 * @see update
	 */
	public void endCRC(){
		this.crc_sum=(~this.crc_sum)&this.tipo.getBitMask();
	}
	/**
	 * Overload do método update para dados no formato int
	 * @see update 
	 * @param data {@link int[]}
	 */
	public void update(int[] data){
		int len=data.length;
		int aux;
		int bitlen=8;
		int shift=this.tipo.getGrau()-bitlen;
		for(int i=0;i<len;i++){
			aux=(int)(((this.crc_sum>>>shift)^data[i])&Mask.MASK8);
			this.crc_sum=(this.crc_sum<<8)^this.lookup_table[aux];
		}
	}
	
	/**
	 * Processa o CRC para um array de bytes
	 * @param data {@link byte[]} Array de bytes
	 */
	public void update(byte[] data){
		int len=data.length;
		int aux;
		long mask=this.tipo.getBitMask();
		for(int i=0;i<len;i++){
			aux=(int)(((this.crc_sum)^data[i])&Mask.MASK8);
			this.crc_sum=((this.crc_sum>>8)^this.lookup_table[aux])&mask;
		}
	}
	/** 
	 * Overload do método crc para dados do tipo {@link int}
	 * @param data {@link int[]} Array de inteiros 
	 * @return {@link long} Valor do CRC computado
	 */
	public long crc(int[] data){
		this.initCRC();
		this.update(data);
		this.endCRC();
		return this.crc_sum;
	}
	
	/**
	 * Método que computa o CRC para um array de bytes
	 * @param data {@link byte[]} Array de bytes para o qual se vai computar o CRC
	 * @return {@link long} Valor do CRC computado
	 */
	public long crc(byte[] data){
		this.initCRC();
		this.update(data);
		this.endCRC();
		return this.crc_sum;
	}
	/**
	 * Método que gera a lookup table de entradas para o CRC definido a partir do {@link CRCType} apontado pelo objecto
	 * @return {@link long[]} Array de constantes que constituem a tabela de lookup
	 */
	public long[] geraCRCTable(){
		return CRC.geraCRCTable(tipo);
	}
	
	private CRCType tipo;
	private long crc_sum;
	private long[] lookup_table;
	/**
	 * Construtor do objecto CRC 
	 * @param tipo {@link CRCType} Enumerado que representa o tipo de Cyclic Redundancy Check a efectuar
	 */
	public CRC(CRCType tipo){
		this.tipo=tipo;
	}
	
	
}

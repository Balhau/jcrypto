package balhau.crypto.checksum;

/**
 * Enumerado que representa os vários tipos (e respectivos polinómios associados) de métodos CRC 
 * (Cyclic Redundancy Check) existentes
 * Note-se que as constantes representam os polinómios em notação Koopman
 * @author balhau
 *
 */
public enum CRCType {
	/**
	 * CRC com polinómio x+1
	 */
	CRC1(0x1,CRC.LASTBITMASK1),
	/**
	 * CRC com polinómio x⁴+x+1
	 */
	CRC4ITU(0xC,CRC.LASTBITMASK4),
	/**
	 * CRC com polinómio x⁵+x³+1
	 */
	CRC5EPC(0x12,CRC.LASTBITMASK5),
	/**
	 * CRC com polinómio x⁵+x⁴+x²+1
	 */
	CRC5ITU(0x15,CRC.LASTBITMASK5),	
	/**
	 * CRC com polinómio x⁵+x²+1
	 */
	CRC5USB(0x14,CRC.LASTBITMASK5),
	/**
	 * CRC com polinomio x⁶+x+1
	 */
	CRC6ITU(0x30,CRC.LASTBITMASK6),
	/**
	 * CRC com polinómio x⁷+x³+1
	 */
	CRC7(0x48,CRC.LASTBITMASK7),
	/**
	 * CRC com polinómio x⁸+x²+x+1
	 */
	CRC8CCITT(0xE0,CRC.LASTBITMASK8),
	/**
	 * CRC com polinómio x⁸+x⁵+x⁴+1
	 */
	CRC8DALLAS(0x8C,CRC.LASTBITMASK8),
	/**
	 * CRC com polinómio x⁸+x⁷+x⁶+x⁴+x²+1
	 */
	CRC8(0xAB,CRC.LASTBITMASK8),
	/**
	 * CRC com polinómio x⁸+x⁴+x³+x²+1
	 */
	CRC8SAE(0xB8,CRC.LASTBITMASK8),
	/**
	 * CRC com polinómio x⁸+x⁷+x⁴+x³+x+1
	 */
	CRC8WCDMA(0xD9,CRC.LASTBITMASK8),
	/**
	 * CRC com polinómio x¹⁰ + x⁹ + x⁵ + x⁴ + x + 1
	 */
	CRC10(0x331,CRC.LASTBITMASK10),
	/**
	 * CRC com polinómio x¹¹ + x⁹+x⁸+x⁷+x²+1
	 */
	CRC11(0x50E,CRC.LASTBITMASK11),
	/**
	 * CRC com polinómio x¹²+x¹¹+x³+x²+1
	 */
	CRC12(0xF01,CRC.LASTBITMASK12),
	/**
	 * CRC com polinómio x¹⁵+x¹⁴+x¹⁰+x⁸+x⁷+x⁴+x³+1 
	 */
	CRC15CAN(0x4CD1,CRC.LASTBITMASK15),
	/**
	 * CRC com polinómio x¹⁶+x¹⁵+x²+1
	 */
	CRC16IBM(0xA001,CRC.LASTBITMASK16),
	/**
	 * CRC com polinómio x¹⁶ + x¹² + x⁵ + 1 
	 */
	CRC16CCITT(0x8408,CRC.LASTBITMASK16),
	/**
	 * CRC com polinómio x¹⁶ + x¹⁵ + x¹¹ + x⁹ + x⁸ + x⁷ + x⁵ + x⁴ + x² + x + 1
	 */
	CRC16T10DIF(0xEDD1,CRC.LASTBITMASK16),
	/**
	 * CRC com polinómio x¹⁶+x¹³+x¹²+x¹¹+x¹⁰+x⁸+x⁶+x⁵+x²+1
	 */
	CRC16DNP(0xA6BC,CRC.LASTBITMASK16),
	/**
	 * CRC com polinómio x¹⁶+x¹⁰+x⁸+x⁷+x³+1
	 */ 
	CRC16DECT(0x91A0,CRC.LASTBITMASK16),
	/**
	 * CRC com polinómio x³²+x²⁶+x²³+x²²+x¹⁶+x¹²+x¹¹+x¹⁰+x⁸+x⁷+x⁵+x⁴+x²+x+1
	 */
	CRC32(0xedb88320,CRC.LASTBITMASK32)	
	;
	/**
	 * Inteiro que representa o polinómio
	 */
	private long poly;
	
	private long lastbitmask;
	
	private CRCType(long polinomio,long lastbitmask){
		this.poly=polinomio;
		this.lastbitmask=lastbitmask;
	}
	/**
	 * Método que devolve o inteiro representando o polinómio na forma Koopman
	 * @return
	 */
	public long getPolinomio(){
		return this.poly;
	}
	/**
	 * Método que devolve o grau do polinómio truncado associado.
	 * @return {@link int} Grau do polinómio
	 */
	public int getLastGrau(){
		int deg=0;
		long aux=this.poly;
		do{
			deg++;
		}while((aux=aux>>>1)!=0);
		return deg;
	}
	
	public int getGrau(){
		int deg=0;
		long aux=lastbitmask;
		do{
			deg++;
		}while((aux=aux>>>1)!=0);
		return deg;
	}
	
	/**
	 * Getter para o bitmask do CRC
	 * @return {@link long	}
	 */
	public long getLastBitMask(){
		return this.lastbitmask;
	}
	
	public long getBitMask(){
		int grau=this.getGrau();
		return (long)(Math.pow(2,grau)-1);
	}
}

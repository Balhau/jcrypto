package balhau.crypto.hash;

import balhau.utils.ArrayUtils;
import balhau.utils.Mask;
import balhau.utils.StringUtils;

/**
 * Hash function desenvolvida por Katholieke Universiteit Leuven e data de 1996<br>
 * <b>Referências:</b><br>
 * <a href="http://homes.esat.kuleuven.be/~bosselae/ripemd160.html">Especificação do algoritmo RIPMED</a><br/>
 * <a href="http://homes.esat.kuleuven.be/~bosselae/ripemd160/ps/AB-9601/rmd160.c">RipMed160 implementação em C ficheiro .c</a><br/>
 * <a href="http://homes.esat.kuleuven.be/~bosselae/ripemd160/ps/AB-9601/rmd160.h">RipMed160 implementação em C ficheiro .h</a><br/>
 * @author balhau 
 *
 */
public class Ripmed160 extends HashFunction implements IHash{
	private int _buff[];
	private byte _chBuff[];
	private int _bf1[];
	private int _bf2[];
	private int _X[];
	private long _pos;
	/*
	 * Constantes para utilização interna ao algoritmo
	 */
	private static int GG_CONST=0x5a827999;
	private static int HH_CONST=0x6ed9eba1;
	private static int II_CONST=0x8f1bbcdc;
	private static int JJ_CONST=0xa953fd4e;
	
	private static int GGG_CONST=0x7a6d76e9;
	private static int HHH_CONST=0x6d703ef3;
	private static int III_CONST=0x5c4dd124;
	private static int JJJ_CONST=0x50a28be6;
	
	public Ripmed160(){
		init();
	}
	
	private void init(){
		_buff=startBuff();
		_bf1=_buff.clone();
		_bf2=_buff.clone();
		_X=new int[16];
		_chBuff=new byte[64];
		_pos=0;
	}
	
	private int[] startBuff(){
		int out[]=new int[5];
		out[0]=0x67452301;
		out[1]=0xefcdab89;
		out[2]=0x98badcfe;
		out[3]=0x10325476;
		out[4]=0xc3d2e1f0;
		return  out;
	}
	
	
	/**
	 * Método que efectua o computo das rondas do algoritmo de Rimped-160
	 */
	private void processBlock(){
//		System.out.println("Buffer de caracteres:");
//		System.out.println(ArrayUtils.ArrayByteHexDesc(_chBuff));
//		System.out.println("Buffer de inteiros:");
		System.out.println(ArrayUtils.ArrayIntHEXDesc(_X));
		System.out.println("IBuff: ["+StringUtils.hex32(_bf1[0])+","+StringUtils.hex32(_bf1[1])+","+StringUtils.hex32(_bf1[2])+","+StringUtils.hex32(_bf1[3])+","+StringUtils.hex32(_bf1[4])+"]");
		//Primeira ronda
		FF(0,_X[0],11);
		FF(4,_X[1],14);
		FF(3,_X[2],15);
		FF(2,_X[3],12);
		FF(1,_X[4],5);
		
		FF(0,_X[5],8);
		FF(4,_X[6],7);
		FF(3,_X[7],9);
		FF(2,_X[8],11);
		FF(1,_X[9],13);
		
		FF(0,_X[10],14);
		FF(4,_X[11],15);
		FF(3,_X[12],6);
		FF(2,_X[13],7);
		FF(1,_X[14],9);
		FF(0,_X[15],8);
		
		//Segunda Ronda
		GG(4,_X[7],7);
		GG(3,_X[4],6);
		GG(2,_X[13],8);
		GG(1,_X[1],13);
		GG(0,_X[10],11);
		
		GG(4,_X[6],9);
		GG(3,_X[15],7);
		GG(2,_X[3],15);
		GG(1,_X[12],7);
		GG(0,_X[0],12);
		
		GG(4,_X[9],15);
		GG(3,_X[5],9);
		GG(2,_X[2],11);
		GG(1,_X[14],7);
		GG(0,_X[11],13);
		GG(4,_X[8],12);
		
		//Terceira Ronda
		HH(3,_X[3],11);
		HH(2,_X[10],13);
		HH(1,_X[14],6);
		HH(0,_X[4],7);
		HH(4,_X[9],14);
		
		HH(3,_X[15],9);
		HH(2,_X[8],13);
		HH(1,_X[1],15);
		HH(0,_X[2],14);
		HH(4,_X[7],8);
		
		HH(3,_X[0],13);
		HH(2,_X[6],6);
		HH(1,_X[13],5);
		HH(0,_X[11],12);
		HH(4,_X[5],7);
		HH(3,_X[12],5);
		
		//Quarta ronda
		II(2,_X[1],11);
		II(1,_X[9],12);
		II(0,_X[11],14);
		II(4,_X[10],15);
		II(3,_X[0],14);
		
		II(2,_X[8],15);
		II(1,_X[12],9);
		II(0,_X[4],8);
		II(4,_X[13],9);
		II(3,_X[3],14);
		
		II(2,_X[7],5);
		II(1,_X[15],6);
		II(0,_X[14],8);
		II(4,_X[5],6);
		II(3,_X[6],5);
		II(2,_X[2],12);
		
		//Quinta ronda
		JJ(1,_X[4],9);
		JJ(0,_X[0],15);
		JJ(4,_X[5],5);
		JJ(3,_X[9],11);
		JJ(2,_X[7],6);
		
		JJ(1,_X[12],8);
		JJ(0,_X[2],13);
		JJ(4,_X[10],12);
		JJ(3,_X[14],5);
		JJ(2,_X[1],12);
		
		JJ(1,_X[3],13);
		JJ(0,_X[8],14);
		JJ(4,_X[11],11);
		JJ(3,_X[6],8);
		JJ(2,_X[15],5);
		JJ(1,_X[13],6);
		
		//Primeira ronda paralela
		JJJ(0,_X[5],8);
		JJJ(4,_X[14],9);
		JJJ(3,_X[7],9);
		JJJ(2,_X[0],11);
		JJJ(1,_X[9],13);
		
		JJJ(0,_X[2],15);
		JJJ(4,_X[11],15);
		JJJ(3,_X[4],5);
		JJJ(2,_X[13],7);
		JJJ(1,_X[6],7);
		
		JJJ(0,_X[15],8);
		JJJ(4,_X[8],11);
		JJJ(3,_X[1],14);
		JJJ(2,_X[10],14);
		JJJ(1,_X[3],12);
		JJJ(0,_X[12],6);
		
		//Segunda ronda paralela
		III(4,_X[6],9);
		III(3,_X[11],13);
		III(2,_X[3],15);
		III(1,_X[7],7);
		III(0,_X[0],12);
		
		III(4,_X[13],8);
		III(3,_X[5],9);
		III(2,_X[10],11);
		III(1,_X[14],7);
		III(0,_X[15],7);
		
		III(4,_X[8],12);
		III(3,_X[12],7);
		III(2,_X[4],6);
		III(1,_X[9],15);
		III(0,_X[1],13);
		III(4,_X[2],11);
		
		//Terceira ronda paralela
		HHH(3,_X[15],9);
		HHH(2,_X[5],7);
		HHH(1,_X[1],15);
		HHH(0,_X[3],11);
		HHH(4,_X[7],8);
		
		HHH(3,_X[14],6);
		HHH(2,_X[6],6);
		HHH(1,_X[9],14);
		HHH(0,_X[11],12);
		HHH(4,_X[8],13);
		
		HHH(3,_X[12],5);
		HHH(2,_X[2],14);
		HHH(1,_X[10],13);
		HHH(0,_X[0],13);
		HHH(4,_X[4],7);
		HHH(3,_X[13],5);
		
		//Quarta ronda paralela
		GGG(2,_X[8],15);
		GGG(1,_X[6],5);
		GGG(0,_X[4],8);
		GGG(4,_X[1],11);
		GGG(3,_X[3],14);
		
		GGG(2,_X[11],14);
		GGG(1,_X[15],6);
		GGG(0,_X[0],14);
		GGG(4,_X[5],6);
		GGG(3,_X[12],9);
		
		GGG(2,_X[2],12);
		GGG(1,_X[13],9);
		GGG(0,_X[9],12);
		GGG(4,_X[7],5);
		GGG(3,_X[10],15);
		GGG(2,_X[14],8);
		
		//Quinta ronda paralela
		FFF(1,_X[12],8);
		FFF(0,_X[15],5);
		FFF(4,_X[10],12);
		FFF(3,_X[4],9);
		FFF(2,_X[1],12);
		
		FFF(1,_X[5],5);
		FFF(0,_X[8],14);
		FFF(4,_X[7],6);
		FFF(3,_X[6],8);
		FFF(2,_X[2],13);
		
		FFF(1,_X[13],6);
		FFF(0,_X[14],5);
		FFF(4,_X[0],15);
		FFF(3,_X[3],13);
		FFF(2,_X[9],11);
		FFF(1,_X[11],11);
		System.out.println("B1: ["+StringUtils.hex32(_bf1[0])+","+StringUtils.hex32(_bf1[1])+","+StringUtils.hex32(_bf1[2])+","+StringUtils.hex32(_bf1[3])+","+StringUtils.hex32(_bf1[4])+"]");
		System.out.println("B2: ["+StringUtils.hex32(_bf2[0])+","+StringUtils.hex32(_bf2[1])+","+StringUtils.hex32(_bf2[2])+","+StringUtils.hex32(_bf2[3])+","+StringUtils.hex32(_bf2[4])+"]");
		//Computo final. Combinação das duas rondas
		System.out.println("FinalBuff: ["+StringUtils.hex32(_buff[0])+","+StringUtils.hex32(_buff[1])+","+StringUtils.hex32(_buff[2])+","+StringUtils.hex32(_buff[3])+","+StringUtils.hex32(_buff[4])+"]");
		int T;
		T=_bf1[2]+_buff[1]+_bf2[3];
		_buff[1]=_buff[2]+_bf1[3]+_bf2[4];
		_buff[2]=_buff[3]+_bf1[4]+_bf2[0];
		_buff[3]=_buff[4]+_bf1[0]+_bf2[1];
		_buff[4]=_buff[0]+_bf1[1]+_bf2[2];
		_buff[0]=T;
	}
	
	private int F(int x,int y,int z){
		return x^y^z;
	}
	
	private int G(int x,int y,int z){
		return (x&y)|((~x)&z);
	}
	
	private int H(int x,int y,int z){
		return (x|(~y))^z;
	}
	
	private int I(int x,int y,int z){
		return (x&z)|(y&(~z));
	}
	
	private int J(int x,int y,int z){
		return x^(y|(~z));
	}
	
	private void FF(int i,int x,int s){
		_bf1[(0+i)%5]+=F(_bf1[(1+i)%5],_bf1[(2+i)%5],_bf1[(3+i)%5])+x;
		_bf1[(0+i)%5]=Integer.rotateLeft(_bf1[(0+i)%5], s)+_bf1[((4+i)%5)];
		_bf1[(2+i)%5]=Integer.rotateLeft(_bf1[(2+i)%5], 10);
		System.out.println("FF ["+StringUtils.hex32(_bf1[(0+i)%5])+","+StringUtils.hex32(_bf1[(1+i)%5])+","+StringUtils.hex32(_bf1[(2+i)%5])+","+StringUtils.hex32(_bf1[(3+i)%5])+","+StringUtils.hex32(_bf1[(4+i)%5])+"]");
		
	}
	
	private void GG(int i,int x,int s){
		_bf1[(0+i)%5]+=G(_bf1[(1+i)%5],_bf1[(2+i)%5],_bf1[(3+i)%5])+x+GG_CONST;
		_bf1[(0+i)%5]=Integer.rotateLeft(_bf1[(0+i)%5], s)+_bf1[((4+i)%5)];
		_bf1[(2+i)%5]=Integer.rotateLeft(_bf1[(2+i)%5], 10);
		System.out.println("GG ["+StringUtils.hex32(_bf1[(0+i)%5])+","+StringUtils.hex32(_bf1[(1+i)%5])+","+StringUtils.hex32(_bf1[(2+i)%5])+","+StringUtils.hex32(_bf1[(3+i)%5])+","+StringUtils.hex32(_bf1[(4+i)%5])+"]");
	}
	
	private void HH(int i,int x,int s){
		_bf1[(0+i)%5]+=H(_bf1[(1+i)%5],_bf1[(2+i)%5],_bf1[(3+i)%5])+x+HH_CONST;
		_bf1[(0+i)%5]=Integer.rotateLeft(_bf1[(0+i)%5], s)+_bf1[((4+i)%5)];
		_bf1[(2+i)%5]=Integer.rotateLeft(_bf1[(2+i)%5], 10);
		System.out.println("HH ["+StringUtils.hex32(_bf1[(0+i)%5])+","+StringUtils.hex32(_bf1[(1+i)%5])+","+StringUtils.hex32(_bf1[(2+i)%5])+","+StringUtils.hex32(_bf1[(3+i)%5])+","+StringUtils.hex32(_bf1[(4+i)%5])+"]");
	}
	
	private void II(int i,int x,int s){
		_bf1[(0+i)%5]+=I(_bf1[(1+i)%5],_bf1[(2+i)%5],_bf1[(3+i)%5])+x+II_CONST;
		_bf1[(0+i)%5]=Integer.rotateLeft(_bf1[(0+i)%5], s)+_bf1[((4+i)%5)];
		_bf1[(2+i)%5]=Integer.rotateLeft(_bf1[(2+i)%5], 10);
		System.out.println("II ["+StringUtils.hex32(_bf1[(0+i)%5])+","+StringUtils.hex32(_bf1[(1+i)%5])+","+StringUtils.hex32(_bf1[(2+i)%5])+","+StringUtils.hex32(_bf1[(3+i)%5])+","+StringUtils.hex32(_bf1[(4+i)%5])+"]");
	}
	
	private void JJ(int i,int x,int s){
		_bf1[(0+i)%5]+=J(_bf1[(1+i)%5],_bf1[(2+i)%5],_bf1[(3+i)%5])+x+JJ_CONST;
		_bf1[(0+i)%5]=Integer.rotateLeft(_bf1[(0+i)%5], s)+_bf1[((4+i)%5)];
		_bf1[(2+i)%5]=Integer.rotateLeft(_bf1[(2+i)%5], 10);
		System.out.println("JJ ["+StringUtils.hex32(_bf1[(0+i)%5])+","+StringUtils.hex32(_bf1[(1+i)%5])+","+StringUtils.hex32(_bf1[(2+i)%5])+","+StringUtils.hex32(_bf1[(3+i)%5])+","+StringUtils.hex32(_bf1[(4+i)%5])+"]");
	}
	
	private void FFF(int i,int x,int s){
		_bf2[(0+i)%5]+=F(_bf2[(1+i)%5],_bf2[(2+i)%5],_bf2[(3+i)%5])+x;
		_bf2[(0+i)%5]=Integer.rotateLeft(_bf2[(0+i)%5], s)+_bf2[((4+i)%5)];
		_bf2[(2+i)%5]=Integer.rotateLeft(_bf2[(2+i)%5], 10);
		System.out.println("FFF ["+StringUtils.hex32(_bf2[(0+i)%5])+","+StringUtils.hex32(_bf2[(1+i)%5])+","+StringUtils.hex32(_bf2[(2+i)%5])+","+StringUtils.hex32(_bf2[(3+i)%5])+","+StringUtils.hex32(_bf2[(4+i)%5])+"]");
	}
	
	private void GGG(int i,int x,int s){
		_bf2[(0+i)%5]+=G(_bf2[(1+i)%5],_bf2[(2+i)%5],_bf2[(3+i)%5])+x+GGG_CONST;
		_bf2[(0+i)%5]=Integer.rotateLeft(_bf2[(0+i)%5], s)+_bf2[((4+i)%5)];
		_bf2[(2+i)%5]=Integer.rotateLeft(_bf2[(2+i)%5], 10);
		System.out.println("GGG ["+StringUtils.hex32(_bf2[(0+i)%5])+","+StringUtils.hex32(_bf2[(1+i)%5])+","+StringUtils.hex32(_bf2[(2+i)%5])+","+StringUtils.hex32(_bf2[(3+i)%5])+","+StringUtils.hex32(_bf2[(4+i)%5])+"]");
	}
	
	private void HHH(int i,int x,int s){
		_bf2[(0+i)%5]+=H(_bf2[(1+i)%5],_bf2[(2+i)%5],_bf2[(3+i)%5])+x+HHH_CONST;
		_bf2[(0+i)%5]=Integer.rotateLeft(_bf2[(0+i)%5], s)+_bf2[((4+i)%5)];
		_bf2[(2+i)%5]=Integer.rotateLeft(_bf2[(2+i)%5], 10);
		System.out.println("HHH ["+StringUtils.hex32(_bf2[(0+i)%5])+","+StringUtils.hex32(_bf2[(1+i)%5])+","+StringUtils.hex32(_bf2[(2+i)%5])+","+StringUtils.hex32(_bf2[(3+i)%5])+","+StringUtils.hex32(_bf2[(4+i)%5])+"]");
	}
	
	private void III(int i,int x,int s){
		_bf2[(0+i)%5]+=I(_bf2[(1+i)%5],_bf2[(2+i)%5],_bf2[(3+i)%5])+x+III_CONST;
		_bf2[(0+i)%5]=Integer.rotateLeft(_bf2[(0+i)%5], s)+_bf2[((4+i)%5)];
		_bf2[(2+i)%5]=Integer.rotateLeft(_bf2[(2+i)%5], 10);
		System.out.println("III ["+StringUtils.hex32(_bf2[(0+i)%5])+","+StringUtils.hex32(_bf2[(1+i)%5])+","+StringUtils.hex32(_bf2[(2+i)%5])+","+StringUtils.hex32(_bf2[(3+i)%5])+","+StringUtils.hex32(_bf2[(4+i)%5])+"]");
	}
	
	private void JJJ(int i,int x,int s){
		_bf2[(0+i)%5]+=J(_bf2[(1+i)%5],_bf2[(2+i)%5],_bf2[(3+i)%5])+x+JJJ_CONST;
		_bf2[(0+i)%5]=Integer.rotateLeft(_bf2[(0+i)%5], s)+_bf2[((4+i)%5)];
		_bf2[(2+i)%5]=Integer.rotateLeft(_bf2[(2+i)%5], 10);
		System.out.println("JJJ ["+StringUtils.hex32(_bf2[(0+i)%5])+","+StringUtils.hex32(_bf2[(1+i)%5])+","+StringUtils.hex32(_bf2[(2+i)%5])+","+StringUtils.hex32(_bf2[(3+i)%5])+","+StringUtils.hex32(_bf2[(4+i)%5])+"]");
	}

	public String encode(String msg) {
		return encode(msg.getBytes());
	}

	public void finish() {
		_X=new int[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};			//Inicializa a variavel de valores inteiros a zero
		int resto=(int)(_pos%64);
		for(int i=0;i<resto;i++){
			_X[i>>2]|=_chBuff[i]<<(8*(i&3));
		}
		
		_X[(resto>>2)&15]|=1<<(8*(resto&3)+7);
		
		if((resto&63)>55){
			processBlock();
			_X=new int[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		}
		_X[14]=resto<<3;
		_X[15]=(resto>>>29);
		processBlock();
	}

	public void update(byte[] block) {
		System.out.println("______________________________________________________________________________________");
		int cmp=block.length;
		int rsto=(int)(_pos%64);
		int diff=64-rsto;
		int i;
		_pos+=cmp;
		System.out.println("Pos: "+_pos);
		//Se o numero de elementos no array forem superiores ou iguais os elementos que faltam para formar
		//um bloco de 512 bits então procede-se à computação dos respectivos blocos
		if(cmp>=diff){
			for(i=0;i<diff;i++){
				_chBuff[rsto+i]=block[i];
			}
			System.out.println("Diff: "+diff);
			System.out.println("CMP: "+cmp);
			System.out.println("Char: "+ArrayUtils.ArrayByteHexDesc(block));
			System.out.println("ChBuff: "+ArrayUtils.ArrayByteHexDesc(_chBuff));
			System.out.println("Resto: "+rsto);
			_X=block64Byte2block16IntRev(_chBuff);
			processBlock();
			rsto=0;
			for(i=diff;i+63<cmp;i+=64){
				rsto=0;
				for(int j=0;j<64;j++){
					_chBuff[j]=block[i+j];
				}
				System.out.println("InnerLoopBuff: "+ArrayUtils.ArrayByteHexDesc(_chBuff));
				_X=block64Byte2block16IntRev(_chBuff);
				processBlock();
			}
		}
		else {
			i=0;
		}
		for(int j=0;j<cmp-i;j++){
			_chBuff[j+rsto]=block[j+i];
		}
	}

	public String hexDigest() {
		String out="";
		for(int i=0;i<_buff.length;i++){
			out+=Integer.toHexString(Integer.reverseBytes(_buff[i]));
		}
		return out;
	}

	public byte[] digest() {
		byte[] dig=new byte[20];
		byte[] aux;
		int step=0;
		for(int i=0;i<_buff.length;i++){
			aux=int32ToByte(Integer.reverseBytes(_buff[i]));
			step=4*i;
			dig[step]=aux[0];dig[step+1]=aux[1];dig[step+2]=aux[2];dig[step+3]=aux[3];
		}
		return dig;
	}

	public String encode(byte[] msg) {
		init();
		update(msg);
		finish();
		return hexDigest();
	}
	
}

import java.io.IOException;
import java.net.SocketTimeoutException;

public class ReceiverThread extends Thread {
	private Object lock;
	private Transmitter trans;
	private boolean die;

	public ReceiverThread(Object lock, Transmitter trans) {
		this.lock = lock;
		this.trans = trans;
		this.die = false;

	}

	public void run() {
		byte[] data;

		while (!die) {
			try {
				data = trans.receive();
				synchronized (lock) {
					System.out.println("Other: " + new String(data));
				}
			} catch (SocketTimeoutException e) {
				// Do nothing ;)
			} catch (IOException e) {
				System.err.println(e.toString());
				break;
			} catch (TransmissionException e) {
				System.err.println(e.toString());
			}
		}

	}

	public void kill() {
		this.die = true;
	}
}

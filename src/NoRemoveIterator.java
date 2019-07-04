import java.util.Iterator;
import java.util.Set;

public class NoRemoveIterator<E> implements Iterator<E> {
    private Iterator<E> wrappedIterator;

    NoRemoveIterator(Iterator<E> i){
        wrappedIterator = i;
    }

    @Override
    public boolean hasNext() {
        return wrappedIterator.hasNext();
    }

    @Override
    public E next() {
        return wrappedIterator.next();
    }

}

import logging
from functools import wraps

# ---- logger setup ----
logging.basicConfig(
    filename="calculator.log",
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("calculator")

def log_call(func):
    """Decorator that logs timestamp, method name, params, and exceptions."""
    @wraps(func)
    def wrapper(a, b):
        logger.info(f"The arguments that were provided -> a:{a}, b:{b} (method={func.__name__})")
        try:
            result = func(a, b)
            logger.info(f"{func.__name__} returned {result}")
            return result
        except Exception as e:
            logger.exception(
                f"Exception in {func.__name__}(a={a}, b={b}): {e}"
            )
            raise
    return wrapper

@log_call
def simpleDiv(a, b):
    return a / b

@log_call
def mul(a, b):
    return a * b

@log_call
def add(a, b):
    return a + b

@log_call
def sub(a, b):
    return a - b

if __name__ == "__main__":
    logger.info("The calculator application has started...")

    add(10, 5)
    mul(3, 1)

    # force an exception so it's logged
    try:
        simpleDiv(10, 0)
    except ZeroDivisionError:
        pass

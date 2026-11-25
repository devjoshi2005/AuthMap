import base64
import os
from io import BytesIO
from PIL import Image
import numpy as np
import logging

logger = logging.getLogger(__name__)

# Hard cap on decoded image size for OCR input (default 5 MiB, override with env).
MAX_OCR_IMAGE_BYTES = int(os.getenv("MAX_OCR_IMAGE_BYTES", str(5 * 1024 * 1024)))

try:
    from rapidocr_onnxruntime import RapidOCR
    ocr_engine = RapidOCR()
except ImportError:
    logger.warning("rapidocr_onnxruntime not installed. OCR will be disabled.")
    ocr_engine = None

def extract_text_from_base64(image_base64: str) -> str:
    """
    Decodes a base64 image and extracts text using RapidOCR.
    """
    if not ocr_engine:
        return ""
        
    try:
        # Strip data URL prefix if present
        if "base64," in image_base64:
            image_base64 = image_base64.split("base64,")[1]

        # Reject oversized payloads before decoding (base64 is ~4/3 the raw size).
        if len(image_base64) > MAX_OCR_IMAGE_BYTES * 2:
            logger.warning(
                "OCR input rejected: base64 payload %d chars exceeds limit of %d bytes",
                len(image_base64),
                MAX_OCR_IMAGE_BYTES,
            )
            return ""

        img_data = base64.b64decode(image_base64, validate=False)
        if len(img_data) > MAX_OCR_IMAGE_BYTES:
            logger.warning(
                "OCR input rejected: decoded image %d bytes exceeds limit of %d bytes",
                len(img_data),
                MAX_OCR_IMAGE_BYTES,
            )
            return ""

        img = Image.open(BytesIO(img_data)).convert('RGB')
        
        # Convert PIL image to numpy array for RapidOCR
        img_array = np.array(img)
        
        result, elapse = ocr_engine(img_array)
        if result:
            # result is a list of items where each item is [box, text, score]
            extracted_text = "\n".join([line[1] for line in result])
            return extracted_text
        return ""
    except Exception as e:
        logger.error(f"OCR Extraction Error: {e}")
        return ""

import base64
from io import BytesIO
from PIL import Image
import numpy as np
import logging

logger = logging.getLogger(__name__)

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
            
        img_data = base64.b64decode(image_base64)
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

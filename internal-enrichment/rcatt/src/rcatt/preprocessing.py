# -*- coding: utf-8 -*-
import io
from pathlib import Path

import pdfplumber


def pdf_to_text(content: bytes, output_path: Path):
    """
    Extract the text (sentences) of a pdf file to a text file.

    # TODO: more cleanup, remove header, footer, noise.

    Parameters
    ----------
    content: bytes
        Content of the pdf file, as bytes.
    output_path : str
        Path for the output text file.
    """
    with pdfplumber.open(io.BytesIO(content)) as pdf:
        sentences = [p.extract_text() for p in pdf.pages]

    with output_path.open(mode="w", encoding="utf-8") as txt:
        for s in sentences:
            txt.write(s)

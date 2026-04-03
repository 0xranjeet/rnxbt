const uploadForm = document.getElementById("uploadForm");
const fileInput = document.getElementById("fileInput");
const uploadButton = document.getElementById("uploadButton");
const fileName = document.getElementById("fileName");
const statusBox = document.getElementById("status");
const resultCard = document.getElementById("resultCard");
const resultName = document.getElementById("resultName");
const resultType = document.getElementById("resultType");
const renameInput = document.getElementById("renameInput");
const renameButton = document.getElementById("renameButton");
const shortLink = document.getElementById("shortLink");
const pageLink = document.getElementById("pageLink");
const imageLink = document.getElementById("imageLink");
const downloadLink = document.getElementById("downloadLink");
const openLinkButton = document.getElementById("openLinkButton");
const downloadLinkButton = document.getElementById("downloadLinkButton");
const dropzone = document.getElementById("dropzone");

const RESUMABLE_UPLOAD_THRESHOLD = 100 * 1024 * 1024;
const TUS_CHUNK_SIZE = 8 * 1024 * 1024;
let isUploading = false;
let currentUpload = null;

function setStatus(message, isError = false) {
  statusBox.textContent = message;
  statusBox.style.color = isError ? "#b42318" : "#6f6558";
}

function setSelectedFile(file) {
  if (!file) {
    fileName.textContent = "No file selected";
    return;
  }

  const sizeInMb = Math.max(file.size / 1024 / 1024, 0.01).toFixed(2);
  fileName.textContent = `${file.name} | ${sizeInMb} MB`;
}

function assignFile(file) {
  const transfer = new DataTransfer();
  transfer.items.add(file);
  fileInput.files = transfer.files;
  setSelectedFile(file);
}

function isAllowedFile(file) {
  if (!file) {
    return false;
  }

  const nextFileName = file.name || "";
  const type = file.type || "";
  const isCsv = type.includes("text/csv") || /\.(csv|scv)$/i.test(nextFileName);
  const isText = (type.startsWith("text/") && !isCsv) || /\.(txt|md|log)$/i.test(nextFileName);

  return isCsv || isText;
}

function showResult(payload) {
  currentUpload = {
    cid: payload.file.cid,
    path: payload.file.storedPath,
    shortCode: payload.file.shortCode,
    type: payload.file.type || "file",
    name: payload.file.name,
  };
  resultCard.classList.remove("hidden");
  resultName.textContent = payload.file.name;
  resultType.textContent = payload.file.type || "file";
  renameInput.value = payload.file.name;
  shortLink.value = payload.links.short;
  pageLink.value = payload.links.page;
  imageLink.value = payload.links.image;
  downloadLink.value = payload.links.download;
  openLinkButton.href = payload.links.page;
  downloadLinkButton.href = payload.links.download;
}

async function parseApiResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  const rawText = await response.text();
  let payload = {};

  if (contentType.includes("application/json")) {
    try {
      payload = rawText ? JSON.parse(rawText) : {};
    } catch (error) {
      payload = {};
    }
  }

  if (!response.ok) {
    const fallbackMessage = rawText.trim();

    if (
      response.status === 413 ||
      fallbackMessage.includes("FUNCTION_PAYLOAD_TOO_LARGE") ||
      fallbackMessage.toLowerCase().includes("request entity too large")
    ) {
      throw new Error("Request body too large on the app server. The upload flow should now send files directly to Pinata, so please retry.");
    }

    throw new Error(payload.error || fallbackMessage || "Request failed.");
  }

  return payload;
}

async function requestSignedUpload(file) {
  const response = await fetch("/api/upload-url", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      name: file.name,
      type: file.type || "text/plain",
      size: file.size,
    }),
  });

  return parseApiResponse(response);
}

function uploadViaSignedPost(file, signedUrl) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const formData = new FormData();
    formData.append("file", file, file.name);

    xhr.open("POST", signedUrl, true);
    xhr.responseType = "json";

    xhr.upload.addEventListener("progress", (event) => {
      if (!event.lengthComputable) {
        return;
      }

      const percent = Math.min(Math.round((event.loaded / event.total) * 100), 100);
      setStatus(`Uploading directly to Pinata... ${percent}%`);
    });

    xhr.addEventListener("error", () => {
      reject(new Error("Could not upload file to Pinata."));
    });

    xhr.addEventListener("load", () => {
      const payload = xhr.response || {};
      if (xhr.status < 200 || xhr.status >= 300) {
        const message = payload?.error?.details || payload?.error?.reason || payload?.message;
        reject(new Error(message || "Direct upload failed."));
        return;
      }

      resolve(payload);
    });

    xhr.send(formData);
  });
}

function uploadViaTus(file, signedUrl) {
  return new Promise((resolve, reject) => {
    if (!window.tus) {
      reject(new Error("Resumable upload library did not load."));
      return;
    }

    const upload = new window.tus.Upload(file, {
      endpoint: signedUrl,
      chunkSize: TUS_CHUNK_SIZE,
      retryDelays: [0, 1000, 3000, 5000],
      metadata: {
        filename: file.name,
        filetype: file.type || "text/plain",
      },
      onError(error) {
        reject(new Error(error?.message || "Large file upload failed."));
      },
      onProgress(bytesUploaded, bytesTotal) {
        const percent = bytesTotal ? Math.min(Math.round((bytesUploaded / bytesTotal) * 100), 100) : 0;
        setStatus(`Uploading large file directly to Pinata... ${percent}%`);
      },
      onSuccess() {
        resolve({
          data: {
            id: upload.url || signedUrl,
          },
        });
      },
    });

    upload.start();
  });
}

async function finalizeUpload({ file, fileId, storedPath, uploadedFile }) {
  const response = await fetch("/api/complete-upload", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      fileId,
      name: file.name,
      storedPath,
      type: file.type || "text/plain",
      uploadedFile,
    }),
  });

  return parseApiResponse(response);
}

async function uploadCurrentFile(file) {
  const signed = await requestSignedUpload(file);
  const useTus = file.size >= RESUMABLE_UPLOAD_THRESHOLD;
  let uploadResult = null;

  if (useTus) {
    uploadResult = await uploadViaTus(file, signed.signedUrl);
  } else {
    uploadResult = await uploadViaSignedPost(file, signed.signedUrl);
  }

  setStatus("Finalizing short link...");
  const uploadedFile = uploadResult?.data || null;

  return finalizeUpload({
    file,
    fileId: uploadedFile?.id || signed.fileId,
    storedPath: uploadedFile?.name || signed.storedName,
    uploadedFile,
  });
}
async function startUpload({ file } = {}) {
  if (isUploading) {
    return;
  }

  isUploading = true;
  uploadButton.disabled = true;
  uploadButton.textContent = "Uploading...";
  setStatus("Preparing direct upload...");

  try {
    const payload = await uploadCurrentFile(file);
    showResult(payload);
    setStatus("Upload complete. Share link ready.");
  } catch (error) {
    setStatus(error.message || "Upload failed.", true);
  } finally {
    isUploading = false;
    uploadButton.disabled = false;
    uploadButton.textContent = "Upload Now";
  }
}

fileInput.addEventListener("change", () => {
  setSelectedFile(fileInput.files[0]);
});

["dragenter", "dragover"].forEach((eventName) => {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragover");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragover");
  });
});

dropzone.addEventListener("drop", (event) => {
  const [file] = event.dataTransfer.files;
  if (!file) {
    return;
  }

  if (!isAllowedFile(file)) {
    setStatus("Only CSV and text files are allowed.", true);
    return;
  }

  assignFile(file);
});

uploadForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const file = fileInput.files[0];
  if (!file) {
    setStatus("Please choose a file first.", true);
    return;
  }

  if (!isAllowedFile(file)) {
    setStatus("Only CSV and text files are allowed.", true);
    return;
  }

  startUpload({ file });
});

renameButton.addEventListener("click", async () => {
  const nextName = renameInput.value.trim();

  if (!currentUpload?.cid) {
    setStatus("Upload a file first.", true);
    return;
  }

  if (!nextName) {
    setStatus("Enter a file name first.", true);
    return;
  }

  renameButton.disabled = true;
  renameButton.textContent = "Updating...";
  setStatus("Updating file name in links...");

  try {
    const response = await fetch("/api/links", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        cid: currentUpload?.cid,
        path: currentUpload?.path,
        shortCode: currentUpload?.shortCode,
        name: nextName,
      }),
    });
    const payload = await parseApiResponse(response);
    const links = payload.links;
    currentUpload.name = nextName;
    resultName.textContent = nextName;
    imageLink.value = links.image;
    pageLink.value = links.page;
    shortLink.value = links.short;
    downloadLink.value = links.download;
    openLinkButton.href = links.page;
    downloadLinkButton.href = links.download;

    setStatus("File name updated in share links.");
  } catch (error) {
    setStatus(error.message || "Could not update file name.", true);
  } finally {
    renameButton.disabled = false;
    renameButton.textContent = "Update Name";
  }
});

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copy);

    try {
      await navigator.clipboard.writeText(target.value);
      setStatus("Link copied.");
    } catch (error) {
      target.select();
      document.execCommand("copy");
      setStatus("Link copied.");
    }
  });
});

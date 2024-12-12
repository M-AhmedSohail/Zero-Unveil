// Select all sidebar menu items and content sections
const allSideMenu = document.querySelectorAll('#sidebar .side-menu li a');
const allSections = document.querySelectorAll('.content-section');
const scanSection = document.getElementById('scan');

// Add click event listener to each menu item
allSideMenu.forEach(item => {
    item.addEventListener('click', function (e) {
        // Check if the link is for logout
        if (item.id === 'logout-link') {
            // Allow the default behavior to proceed
            return;
        }

        e.preventDefault(); // Prevent default anchor behavior for other items

        // Remove 'active' class from all sections
        allSections.forEach(section => {
            section.classList.remove('active');
        });

        // Get the target content section from data-target attribute
        const targetSection = document.getElementById(item.getAttribute('data-target'));

        // Add 'active' class to the target section
        targetSection.classList.add('active');

        // Remove 'active' class from all sidebar <li> elements
        allSideMenu.forEach(i => i.parentElement.classList.remove('active'));

        // Add 'active' class to the parent <li> of the clicked item
        item.parentElement.classList.add('active');
    });
});

// TOGGLE SIDEBAR
const menuBar = document.querySelector('#content nav .bx.bx-menu');
const sidebar = document.getElementById('sidebar');

menuBar.addEventListener('click', function () {
    sidebar.classList.toggle('hide');
});

// SEARCH BUTTON TOGGLE BEHAVIOR
const searchButton = document.querySelector('#content nav form .form-input button');
const searchButtonIcon = document.querySelector('#content nav form .form-input button .bx');
const searchForm = document.querySelector('#content nav form');

searchButton.addEventListener('click', function (e) {
    if (window.innerWidth < 576) {
        e.preventDefault();
        searchForm.classList.toggle('show');
        if (searchForm.classList.contains('show')) {
            searchButtonIcon.classList.replace('bx-search', 'bx-x');
        } else {
            searchButtonIcon.classList.replace('bx-x', 'bx-search');
        }
    }
});

// HIDE SIDEBAR ON SMALL SCREENS
if (window.innerWidth < 768) {
    sidebar.classList.add('hide');
} else if (window.innerWidth > 576) {
    searchButtonIcon.classList.replace('bx-x', 'bx-search');
    searchForm.classList.remove('show');
}

window.addEventListener('resize', function () {
    if (this.innerWidth > 576) {
        searchButtonIcon.classList.replace('bx-x', 'bx-search');
        searchForm.classList.remove('show');
    }
});

// TOGGLE DARK MODE
const switchMode = document.getElementById('switch-mode');

switchMode.addEventListener('change', function () {
    if (this.checked) {
        document.body.classList.add('dark');
    } else {
        document.body.classList.remove('dark');
    }
});

// DRAG AND DROP FILE UPLOAD FUNCTIONALITY
document.addEventListener('DOMContentLoaded', function () {
    const dropArea = document.querySelector('.drag-drop-area');
    const fileInput = document.getElementById('file-input');
    const fileInfo = document.getElementById('file-info');

    dropArea.addEventListener('dragover', function (event) {
        event.preventDefault();
        dropArea.classList.add('highlight');
    });

    dropArea.addEventListener('dragleave', function () {
        dropArea.classList.remove('highlight');
    });

    dropArea.addEventListener('drop', function (event) {
        event.preventDefault();
        dropArea.classList.remove('highlight');
        const files = event.dataTransfer.files;
        if (files.length) {
            fileInput.files = files; // Assign dropped files to the file input
            displayFileInfo(files[0]); // Display file information
            uploadFile(files[0]);  // Upload the file to the server
        }
    });

    dropArea.addEventListener('click', function () {
        fileInput.click(); // Trigger the file input click
    });

    fileInput.addEventListener('change', function () {
        displayFileInfo(fileInput.files[0]); // Display file information
        uploadFile(fileInput.files[0]);  // Upload the file to the server
    });

    function displayFileInfo(file) {
        if (file) {
            fileInfo.innerText = `File Name: ${file.name}, File Size: ${file.size} bytes`;
        }
    }

    /*function uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            console.log('Response data:', data); // Log the actual data returned from the server

            // Display the file information first
            fileInfo.innerHTML = `File Name: ${file.name}, File Size: ${file.size} bytes`;

            // Create a wrapper for centering content
            const resultWrapper = document.createElement('div');
            resultWrapper.style.display = 'flex';
            resultWrapper.style.flexDirection = 'column';
            resultWrapper.style.alignItems = 'center';
            resultWrapper.style.marginTop = '20px';

            // Display the binary result (Malicious/Benign)
            const resultElement = document.createElement('p');
            resultElement.className = 'result'; // Apply the result class for general styling
            resultElement.innerText = `Detection Result: ${data.binary_result}`;

            // Apply class based on the result to change the color
            if (data.binary_result === 'Malicious') {
                resultElement.classList.add('malicious');
            } else {
                resultElement.classList.add('benign');
            }

            // Append the binary result to the file info section
            resultWrapper.appendChild(resultElement);

            scrollToBottom(scanSection);

            // If multi-class result exists, show it along with the button for LIME explanation
            if (data.binary_result === 'Malicious' && data.multiclass_result) {
                const categoryElement = document.createElement('p');
                categoryElement.className = 'category'; // Apply category styling
                categoryElement.innerText = `Malware Category: ${data.multiclass_result}`;
                resultWrapper.appendChild(categoryElement);

                // Create a button for generating LIME explanation
                const limeButton = document.createElement('button');
                limeButton.className = 'lime-button'; // Add your styling class
                limeButton.innerText = 'Generate LIME Explanation';

                // Append button and a wrapper to center the button
                const buttonWrapper = document.createElement('div');
                buttonWrapper.className = 'center-button'; // Add class for centering the button
                buttonWrapper.appendChild(limeButton);
                resultWrapper.appendChild(buttonWrapper);

                // Add explain_text and complete_text placeholders
                const explainText = document.createElement('div');
                explainText.className = 'lime-explanation-details';
                explainText.innerText = `Explain Text: ${data.explain_text || 'No explanation available.'}`;

                const completeText = document.createElement('div');
                completeText.className = 'lime-explanation-details';
                completeText.innerText = `Complete Text: ${data.complete_text || 'No complete explanation available.'}`;

                // Create a paragraph that will be displayed below the button when clicked
                const limeExplanationParagraph = document.createElement('p');
                limeExplanationParagraph.className = 'lime-explanation-paragraph';
                limeExplanationParagraph.innerHTML = `
                    <strong>The output from LIME (Local Interpretable Model-Agnostic Explanations) for explaining a malware classification system:</strong>
                    <br/><br/>
                    <strong>1. Prediction Probabilities (Left Section)</strong><br/>
                    • This section shows the predicted class probabilities for the given malware sample. In your case, the system is classifying the sample as one of several malware families or types.<br/>
                    • Each row represents a class (e.g., Obfuscator.ACY, Kelihos_ver1, Kelihos_ver3, Vundo, Other) with their corresponding predicted probability.<br/>
                    • The color shading behind the probabilities might represent the intensity or confidence in the prediction, with darker colors representing higher confidence.<br/><br/>
                    
                    <strong>2. Class Prediction (Top Center Section)</strong><br/>
                    • This part seems to display the final prediction result from your classifier, which appears to be a binary decision between two possible states.<br/>
                    • The system is deciding whether the malware sample is classified as the result category or not, based on the probabilities.<br/><br/>
                    
                    <strong>3. Feature Importance (Middle Section)</strong><br/>
                    • This section represents the important features that influenced the classification decision. LIME explains how much each feature (e.g., opcodes) contributed to the classification.<br/>
                    • For each opcode (assembly instructions like add, jmp, inc, call, etc.), you have a corresponding weight (value). The higher the weight, the more that feature contributed to the classification result.<br/>
                    • These features are part of the opcodes extracted from the malware's assembly code.<br/><br/>
                    
                    <strong>4. Feature Table (Right Section)</strong><br/>
                    • This table shows detailed values of the features used in the prediction. It corresponds to the opcodes (features) from the malware sample and how they influenced the final prediction.<br/>
                    • The "Feature" column lists each opcode, while the "Value" column gives the associated impact (influence) that feature had on the decision.<br/>
                    • Negative values (e.g., jmp = -0.30) indicate that the feature is pushing the classifier towards the NOT result decision, while positive values would push towards the category result.<br/><br/>
                    
                    <strong>Summary of the LIME Explanation:</strong><br/>
                    • The LIME explanation shows how different opcodes (features) from the malware sample influenced the classification decision.<br/>
                    • The Prediction Probabilities section shows how likely the sample belongs to each malware family (Obfuscator.ACY, Kelihos, etc.).<br/>
                    • The Feature Importance section highlights which opcodes played a significant role in classifying the sample, and whether they pushed the classifier towards or away from the Obfuscator.ACY label.<br/>
                    • The Feature Table gives detailed values indicating how much each opcode (e.g., jmp, inc, call) contributed to the decision.<br/>
                    <br/>
                    In this case, LIME is showing how different opcodes impacted the model’s decision, which provides interpretability on why your malware classifier made a particular prediction.
                `;
                limeExplanationParagraph.style.display = 'none'; // Initially hidden
                explainText.style.display = 'none'; // Show explain_text
                completeText.style.display = 'none'; // Show complete_text

                resultWrapper.appendChild(explainText); // Append explain_text
                resultWrapper.appendChild(completeText); // Append complete_text
                resultWrapper.appendChild(limeExplanationParagraph);
                

                // Button click event to show the paragraph and open the LIME explanation
                limeButton.onclick = function() {
                    //window.open('/lime-explanation', '_blank');  // Open LIME explanation in a new tab
                    //limeExplanationParagraph.style.display = 'block'; // Show LIME explanation
                    
                    explainText.style.display = 'block'; // Show explain_text
                    completeText.style.display = 'block'; // Show complete_text
                    scrollToBottom(scanSection);
                    
                    
                };
            }

            // Append the centered wrapper to the fileInfo section
            fileInfo.appendChild(resultWrapper);

            // Scroll to the bottom of the scan section
            scrollToBottom(scanSection);

        })
        .catch(error => {
            console.error('Error:', error);  // Log any errors for debugging
            const errorElement = document.createElement('p');
            errorElement.className = 'error';
            errorElement.innerText = 'An error occurred while uploading the file.';
            fileInfo.appendChild(errorElement);
        });
    }
}); */

function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    // Display the file information first
    fileInfo.innerHTML = `File Name: ${file.name}, File Size: ${file.size} bytes`;

    // Show the loader
    showLoader(fileInfo);

    fetch('/upload', {
        method: 'POST',
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            console.log('Response data:', data);

            

            // Ensure the loader is displayed for at least 2 seconds
            setTimeout(() => {
                // Hide the loader
                hideLoader(fileInfo);

                // Display the results
                const resultWrapper = document.createElement('div');
                resultWrapper.style.display = 'flex';
                resultWrapper.style.flexDirection = 'column';
                resultWrapper.style.alignItems = 'center';

                // Binary result
                const resultElement = document.createElement('p');
                resultElement.className = 'result';
                resultElement.innerText = `Detection Result: ${data.binary_result}`;
                resultElement.style.marginBottom = '20px';
                if (data.binary_result === 'Malicious') {
                    resultElement.classList.add('malicious');
                } else {
                    resultElement.classList.add('benign');
                }
                resultWrapper.appendChild(resultElement);

                // Multi-class result
                if (data.binary_result === 'Malicious' && data.multiclass_result) {
                    const categoryElement = document.createElement('p');
                    categoryElement.className = 'category';
                    categoryElement.innerText = `Malware Category: ${data.multiclass_result}`;
                    resultWrapper.appendChild(categoryElement);

                    // Create a container for the buttons
                    const buttonContainer = document.createElement('div');
                    buttonContainer.className = 'button-container';

                    // LIME button
                    const limeButton = document.createElement('button');
                    limeButton.className = 'lime-button';
                    limeButton.innerText = 'Generate LIME Explanation';

                    // Create the "Visualize LIME" button
                    const visualizeButton = document.createElement('button');
                    visualizeButton.className = 'visualize-button';
                    visualizeButton.innerText = 'Visualize LIME';

                    // Append both buttons to the container
                    buttonContainer.appendChild(limeButton);
                    buttonContainer.appendChild(visualizeButton);
                    resultWrapper.appendChild(buttonContainer);

                    const limeExplanationParagraph = document.createElement('p');
                    limeExplanationParagraph.className = 'lime-explanation-paragraph';
                    limeExplanationParagraph.innerText = `LIME Explanation:`;

                    const explainText = document.createElement('div');
                    explainText.className = 'lime-explanation-details';
                    explainText.innerText = ` ${data.explain_text || 'No explanation available.'}`;

                    const completeText = document.createElement('div');
                    completeText.className = 'lime-explanation-details';
                    completeText.innerText = ` ${data.complete_text || 'No complete explanation available.'}`;

                    limeExplanationParagraph.style.display = 'none';
                    explainText.style.display = 'none'; // Show explain_text
                    completeText.style.display = 'none'; // Show complete_text

                    resultWrapper.appendChild(limeExplanationParagraph);
                    resultWrapper.appendChild(explainText);
                    resultWrapper.appendChild(completeText);

                    limeButton.onclick = function () {
                        limeExplanationParagraph.style.display = 'block';
                        explainText.style.display = 'block';
                        completeText.style.display = 'block';

                        // Scroll to the bottom of the scan section
                        scrollToBottom(scanSection);
                        //window.open('/lime-explanation', '_blank');  // Open LIME explanation in a new tab
                    };
                    visualizeButton.onclick = function () {
                        window.open('/lime-explanation', '_blank'); // Open LIME visualization in a new tab
                    };
                }

                fileInfo.appendChild(resultWrapper);
                scrollToBottom(scanSection);
            }, 2000); // Minimum 2 seconds delay
        })
        .catch(error => {
            console.error('Error:', error);

            // Ensure the loader is displayed for at least 2 seconds
            setTimeout(() => {
                hideLoader(fileInfo);

                const errorElement = document.createElement('p');
                errorElement.className = 'error';
                errorElement.innerText = 'An error occurred while uploading the file.';
                fileInfo.appendChild(errorElement);

                scrollToBottom(scanSection);
            }, 2000); // Minimum 2 seconds delay
        });
}
});


function scrollToBottom(container) {
    container.scrollTop = container.scrollHeight;
}

function showLoader(container) {
    //container.innerHTML = ''; // Clear previous content
    const loader = document.createElement('div');
    loader.className = 'loader';
    loader.innerHTML = `<div class="spinner"></div><p>Loading...</p>`;
    container.appendChild(loader);
}

function hideLoader(container) {
    const loader = container.querySelector('.loader'); // Select only the loader
    if (loader) {
        loader.remove(); // Remove the loader without clearing other content
    }
}
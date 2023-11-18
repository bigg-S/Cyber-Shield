#define NOMINMAX

#include "ml_model.h"

namespace PacketAnalyzer
{

	KNN::KNN(int val)
	{
		k = val;
		neighbors = nullptr;
		trainingData = nullptr;
		testData = nullptr;
		validationData = nullptr;
	}

	KNN::KNN()
	{
		k = 3; // Default value for k
		neighbors = nullptr;
		trainingData = nullptr;
		testData = nullptr;
		validationData = nullptr;
	}

	KNN::~KNN()
	{
		// Cleaning up
	}

	template<class Archive>
	void KNN::serialize(Archive& ar, const unsigned int version)
	{
		ar& k;
		ar& neighbors;
		ar& trainingData;
		ar& testData;
		ar& validationData;
	}

	// save KNN instance
	void KNN::SaveKNN(std::string& fileName)
	{
		std::ofstream ofs(fileName);
		boost::archive::text_oarchive oa(ofs);
		oa << *this;
	}

	// load the KNN instace
	void KNN::LoadKNN(std::string& fileName)
	{
		std::ifstream ifs(fileName);
		boost::archive::text_iarchive ia(ifs);
		ia >> *this;
	}

	void KNN::FindKNearest(std::shared_ptr<DataCollection::Data> queryPoint)
	{
		// a vector to store distances and corresponding data points
		std::vector<std::pair<double, std::shared_ptr<DataCollection::Data>>> distancesAndPoints;

		// storing the distances and corresponding data points
		if (trainingData != nullptr)
		{
			for (int j = 0; j < trainingData->size(); j++)
			{
				double distance = CalculateDistance(queryPoint, trainingData->at(j), DistanceMetric::EUCLID);
				distancesAndPoints.emplace_back(distance, trainingData->at(j));
			}
		}
		else
		{
			std::cout << "No training data" << std::endl;
			return;
		}
		

		// sort distances and take the top k neighbors
		std::sort(distancesAndPoints.begin(), distancesAndPoints.end(), [](const auto& a, const auto& b) {return a.first < b.first; });

		// Extract k neighbors
		neighbors = std::make_shared<std::vector<std::shared_ptr<DataCollection::Data>>>();

		for (int i = 0; i < k; i++)
		{
			neighbors->push_back(distancesAndPoints[i].second);
		}
	}


	void KNN::SetTrainingData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		trainingData = vect;
	}

	void KNN::SetTestData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		testData = vect;
	}

	void KNN::SetValidationData(std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>> vect)
	{
		validationData = vect;
	}

	void KNN::SetK(int val) // change k without reloading the data
	{
		k = val;
	}

	std::string KNN::Predict() // return predicted class
	{
		// Ensure neighbors is not empty
		if (neighbors->empty() || neighbors == nullptr)
		{
			std::cerr << "Error: No neighbors to make a prediction." << std::endl;
			return ""; // You might want to handle this case appropriately
		}

		// Create a map to store the count of each label
		std::map<std::string, int> classFreq;

		// Count occurrences of each label among neighbors
		for (const auto& neighbor : *neighbors) 
		{
			std::string label = neighbor->GetLabel();
			classFreq[label]++;
		}

		// Count occurrences with the maximum count(majority vote)
		auto best = std::max_element(classFreq.begin(), classFreq.end(), [](const auto& a, const auto& b) {return a.second < b.second; });
		
		return best->first;
	}

	// calculate the distance from the current datapoint to a given training datapoint
	double KNN::CalculateDistance(std::shared_ptr<DataCollection::Data> queryPoint, std::shared_ptr<DataCollection::Data> input, DistanceMetric metric)
	{
		double distance = 0.0;
		if (queryPoint->GetFeatureVectorSize() != input->GetFeatureVectorSize())
		{
			std::cerr<<"Error: Vector Size mismatch\n";
			exit(1);
		}

		for (int i = 0; i < queryPoint->GetFeatureVectorSize(); i++)
		{
			if (metric == DistanceMetric::EUCLID)
			{
				distance += pow(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i), 2);
			}
			else if(metric == DistanceMetric::MANHATTAN)
			{
				distance += abs(queryPoint->GetFeatureVector()->at(i) - input->GetFeatureVector()->at(i));
			}
		}

		if (metric == DistanceMetric::EUCLID)
		{
			return sqrt(distance);
		}
		else
		{
			return distance;
		}
		
	}

	const std::vector<std::string>& KNN::GetTrueLabels() const
	{
		return trueLabels;
	}

	const std::vector<std::string>& KNN::GetPredictedLabels() const
	{
		return predictedLabels;
	}

	std::string KNN::InspectDataPoint(std::shared_ptr<DataCollection::Data> data)
	{
		// Log start of testing
		std::cout << "Starting performance testing" << std::endl;

		std::string prediction;

		// clear the lists to store the true predicted labels
		trueLabels.clear();
		predictedLabels.clear();

		// Initialize variables for silhouette score calculation
		double totalSilhouetteScore = 0.0;

		
		FindKNearest(data);
		prediction = Predict();

		trueLabels.push_back(data->GetLabel());
		predictedLabels.push_back(prediction);

		// Calculate silhouette score for the current test data point
		double silhouetteScore = CalculateSilhouetteScore(data);
		totalSilhouetteScore += silhouetteScore;

		neighbors->clear();			

		// Calculate and log average silhouette score
		double averageSilhouetteScore = totalSilhouetteScore;//  / testData->size();
		std::cout << "Average Silhouette Score: " << averageSilhouetteScore * 100 << "%" << std::endl;

		std::cout << "Predicted value: " << prediction << std::endl;

		// Log end of testing
		std::cout << "Finished performance testing" << std::endl;

		return prediction;
	}

	double KNN::ValidatePerformance()
	{
		double currentPerformance = 0;
		int count = 0;
		int dataIndex = 0;

		for (std::shared_ptr<DataCollection::Data> queryPoint : *validationData)
		{
			FindKNearest(queryPoint);
			std::string prediction = Predict();
			if (prediction == queryPoint->GetLabel())
			{
				count++;
			}
			dataIndex++;
			//printf("Current Performance = %.3f %%\n", ((double)count * 100.0 / ((double)dataIndex)));
		}
		currentPerformance = ((double)count * 100) / ((double)validationData->size());
		printf("Validation performance for k = %d = %.3f %%\n", k, ((double)count * 100.0 / ((double)validationData->size())));
		return currentPerformance;
	}

	double KNN::CalculateSilhouetteScore(std::shared_ptr<DataCollection::Data> queryPoint)
	{
		const size_t numNeighbors = neighbors->size();

		if (numNeighbors == 0 || numNeighbors >= trainingData->size()) {
			std::cerr << "Error: Invalid number of neighbors for silhouette score calculation." << std::endl;
			return 0.0;
		}

		double silhouetteScore = 0.0;

		for (int i = 0; i < numNeighbors; ++i)
		{
			double a = CalculateDistance(queryPoint, neighbors->at(i), DistanceMetric::EUCLID);

			// Calculate average distance to other data points in the training set
			std::vector<double> distancesToOthers;
			for (int j = 0; j < trainingData->size(); ++j)
			{
				if (std::find(neighbors->begin(), neighbors->end(), trainingData->at(j)) == neighbors->end()) 
				{
					distancesToOthers.push_back(CalculateDistance(queryPoint, trainingData->at(j), DistanceMetric::EUCLID));
				}
			}

			double b = distancesToOthers.empty() ? 0.0 : std::accumulate(distancesToOthers.begin(), distancesToOthers.end(), 0.0) / distancesToOthers.size();

			// Calculate silhouette score for the current neighbor
			double currentScore = (b - a) / std::max(a, b);
			silhouetteScore += currentScore;
		}

		// Average silhouette score over all neighbors
		silhouetteScore /= numNeighbors;

		return silhouetteScore;
	}

	double KNN::TestPerformance(const std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& testData)
	{
		// Log start of testing
		std::cout << "Starting performance testing" << std::endl;

		double accuracy = 0.0;
		double precision = 0.0;
		double recall = 0.0;
		double f1Score = 0.0;
		std::vector<std::vector<int>> confusionMatrix;

		double currentPerformance = 0.0;
		int count = 0;
		
		// clear the lists to store the true predicted labels
		trueLabels.clear();
		predictedLabels.clear();

		// Initialize variables for silhouette score calculation
		double totalSilhouetteScore = 0.0;

		for (std::shared_ptr<DataCollection::Data> queryPoint : *testData)
		{
			FindKNearest(queryPoint);
			std::string prediction = Predict();

			trueLabels.push_back(queryPoint->GetLabel());
			predictedLabels.push_back(prediction);
			if (prediction == queryPoint->GetLabel())
			{
				count++;
			}

			// Calculate silhouette score for the current test data point
			double silhouetteScore = CalculateSilhouetteScore(queryPoint);
			totalSilhouetteScore += silhouetteScore;

			neighbors->clear();
		}

		// Calculate and log average silhouette score
		double averageSilhouetteScore = totalSilhouetteScore / testData->size();
		std::cout << "Average Silhouette Score: " << averageSilhouetteScore * 100 << "%" << std::endl;

		//accuracy = static_cast<double>(count) / testData->size();
		//
		//currentPerformance = ((double)count * 100) / ((double)testData->size());
		//printf("Test performance = %.3f %%\n", currentPerformance);
		//
		//// log accuracy
		//std::cout << "Accuracy: " << accuracy * 100 <<  std::endl;
		//
		//// Calculate and log precision
		//precision = CalculatePrecision(testData);
		//std::cout << "Precision: " << precision * 100 << std::endl;
		//
		//// Calculate and log recall
		//recall = CalculateRecall(testData);
		//std::cout << "Recall: " << recall * 100 << std::endl;
		//
		//// Calculate and log F1 score
		//f1Score = CalculateF1Score(testData);
		//std::cout << "F1 Score: " << f1Score << std::endl;
		//
		//// Calculate and log confusion matrix
		//CalculateConfusionMatrix(testData, confusionMatrix);
		//std::cout << "Confusion matrix:" << std::endl;
		//for (auto& row : confusionMatrix) 
		//{
		//	for (auto count : row) 
		//	{
		//		std::cout << count << " ";
		//	}
		//	std::cout << std::endl;
		//}

		// Log end of testing
		std::cout << "Finished performance testing" << std::endl;

		return averageSilhouetteScore;
	}

	// Calculate precision
	double KNN::CalculatePrecision(const std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data) {
		if (!data || !data->size()) 
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return 0.0;
		}

		int truePositives = 0;
		int falsePositives = 0;

		for (size_t i = 0; i < data->size(); i++) 
		{
			FindKNearest(data->at(i));
			std::string prediction = Predict();
			if (prediction == "anomaly" && data->at(i)->GetLabel() == "anomaly") 
			{
				truePositives++;
			}
			if (prediction == "anomaly" && data->at(i)->GetLabel() == "normal") 
			{
				falsePositives++;
			}
		}

		if (truePositives + falsePositives == 0) 
		{
			return 0.0;
		}

		return static_cast<double>(truePositives) / (truePositives + falsePositives);
	}

	// Calculate recall
	double KNN::CalculateRecall(const std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data) {
		if (!data || !data->size()) 
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return 0.0;
		}

		int truePositives = 0;
		int falseNegatives = 0;

		for (size_t i = 0; i < data->size(); i++) 
		{
			FindKNearest(data->at(i));
			std::string prediction = Predict();
			if (prediction == "anomaly" && data->at(i)->GetLabel() == "anomaly") 
			{
				truePositives++;
			}
			if (prediction == "normal" && data->at(i)->GetLabel() == "anomaly") 
			{
				falseNegatives++;
			}
		}

		if (truePositives + falseNegatives == 0) 
		{
			return 0.0;
		}

		return static_cast<double>(truePositives) / (truePositives + falseNegatives);
	}

	// Calculate F1-score
	double KNN::CalculateF1Score(const std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data)
	{
		if (!data || !data->size())
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return 0.0;
		}

		double precision = CalculatePrecision(data);
		double recall = CalculateRecall(data);

		if (precision + recall == 0) 
		{
			return 0.0;
		}

		return 2.0 * (precision * recall) / (precision + recall);
	}

	// Calculate confusion matrix
	void KNN::CalculateConfusionMatrix(const std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>& data, std::vector<std::vector<int>>& confusionMatrix)
	{
		if (!data || !data->size()) 
		{
			std::cerr << "Error: Invalid data or label input." << std::endl;
			return;
		}

		confusionMatrix = std::vector<std::vector<int>>(2, std::vector<int>(2, 0));

		for (size_t i = 0; i < data->size(); i++) 
		{
			FindKNearest(data->at(i));
			std::string prediction = Predict();
			if (data->at(i)->GetLabel() == "normal") 
			{
				if (prediction == "normal") 
				{
					confusionMatrix[0][0]++; // True negatives
				}
				else 
				{
					confusionMatrix[0][1]++; // False positives
				}
			}
			else 
			{
				if (prediction == "anomaly") 
				{
					confusionMatrix[1][1]++; // True positives
				}
				else 
				{
					confusionMatrix[1][0]++; // False negatives
				}
			}
		}
	}

	// Cross-validation
	double KNN::CrossValidation(int numFolds) {
		if (!validationData) 
		{
			std::cerr << "Error: Validation data not set." << std::endl;
			return 0.0;
		}

		size_t foldSize = validationData->size() / numFolds;
		double totalAccuracy = 0.0;

		for (int fold = 0; fold < numFolds; fold++) 
		{
			std::shared_ptr<std::vector<std::shared_ptr<DataCollection::Data>>>
				validationFold(new std::vector<std::shared_ptr<DataCollection::Data>>());
			std::shared_ptr<std::vector<std::string>> labelsFold(new std::vector<std::string>());

			// Split data into folds
			for (size_t i = 0; i < validationData->size(); i++) 
			{
				if (i >= fold * foldSize && i < (fold + 1) * foldSize) 
				{
					validationFold->push_back(validationData->at(i));
					labelsFold->push_back(validationData->at(i)->GetLabel());
				}
			}

			SetValidationData(validationFold);
			double accuracy = ValidatePerformance();
			totalAccuracy += accuracy;
		}

		// Average accuracy over folds
		return totalAccuracy / numFolds;
	}
}